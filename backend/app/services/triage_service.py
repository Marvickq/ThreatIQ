"""Automatic triage of high-priority alerts.

After a NEW alert is persisted, a background `analyze` job is queued for HIGH and CRITICAL alerts when the
organization has turned automatic triage on (off by default). The job is the existing analysis job: it
gathers evidence (honouring the organization's external-enrichment setting), calls the model under the
AI_CONCURRENCY limit, validates the output and stores an assessment for a human to review.

Guarantees:
- Nothing here runs in the ingest request beyond a counter check and a database insert; no model call.
- The AI only advises. Triage never resolves an alert, records a decision or takes a response action.
- One automatic job per alert (idempotency key), and none if an analysis is already queued or running.
- A failure to enqueue is audited and swallowed: the ingested alert is never lost or rolled back.
- Automatic analyses share the organization's hourly AI budget and have their own, lower cap.
- Audit details hold IDs, counts and error codes only, never alert content.
"""
import logging

from sqlmodel import Session, select

from app import jobs, ratelimit
from app.ai.nebius_client import NebiusClient
from app.config import get_settings
from app.models import Job, Organization, SecurityAlert
from app.services.audit_service import record_event
from app.services.investigation_service import active_analysis_job

logger = logging.getLogger(__name__)

AUTO_SEVERITIES = frozenset({"high", "critical"})


def idempotency_key(alert_id: str) -> str:
    return f"auto-triage:{alert_id}"


def _skip(session: Session, organization_id: str, alert_id: str, reason: str) -> None:
    record_event(session, organization_id, alert_id, "auto_triage_skipped", "system", None, {"reason": reason})
    session.commit()


def maybe_enqueue(session: Session, organization_id: str, alert_id: str) -> Job | None:
    """Queue automatic triage for a newly created alert if it qualifies. Never raises."""
    try:
        return _maybe_enqueue(session, organization_id, alert_id)
    except Exception as exc:
        logger.exception("Automatic triage enqueue failed", extra={"alert_id": alert_id})
        try:
            session.rollback()
            record_event(session, organization_id, alert_id, "auto_triage_failed", "system", None,
                         {"stage": "enqueue", "error_type": type(exc).__name__})
            session.commit()
        except Exception:
            session.rollback()
            logger.exception("Could not record the automatic triage failure", extra={"alert_id": alert_id})
        return None


def _maybe_enqueue(session: Session, organization_id: str, alert_id: str) -> Job | None:
    alert = session.get(SecurityAlert, alert_id)
    if alert is None or alert.organization_id != organization_id or alert.is_demo or alert.severity not in AUTO_SEVERITIES:
        return None
    org = session.get(Organization, organization_id)
    if org is None or not org.auto_triage_enabled:
        return None

    key = idempotency_key(alert.id)
    existing = session.exec(select(Job).where(Job.organization_id == organization_id, Job.idempotency_key == key)).first()
    if existing is not None or active_analysis_job(session, organization_id, alert.id) is not None:
        return existing  # already covered; an analyst or an earlier attempt got there first

    settings = get_settings()
    if not NebiusClient(settings).is_configured:
        _skip(session, organization_id, alert.id, "model_not_configured")
        return None
    # Automatic work is capped below the organization's hourly AI limit and also counts against it.
    allowed, _ = ratelimit.hit(f"ai-auto:{organization_id}", settings.auto_triage_max_per_hour, 3600)
    if allowed:
        allowed, _ = ratelimit.hit(f"ai:{organization_id}", settings.rate_limit_ai_per_hour, 3600)
    if not allowed:
        _skip(session, organization_id, alert.id, "rate_limited")
        return None

    job = jobs.enqueue(session, organization_id, "analyze", payload={"auto": True}, subject_id=alert.id, idempotency_key=key)
    record_event(session, organization_id, alert.id, "auto_triage_enqueued", "system", None,
                 {"job_id": job.id, "severity": alert.severity})
    session.commit()
    return job
