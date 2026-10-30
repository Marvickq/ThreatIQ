from fastapi import APIRouter, Depends, Header, Query, Response
from sqlmodel import Session

from app import jobs, ratelimit
from app.auth.deps import require
from app.auth.principal import Principal
from app.config import get_settings
from app.database import get_session
from app.errors import AppError
from app.models import utcnow
from app.schemas_saas import BatchIngestAccepted, IngestBatch, IngestEvent, IngestResult
from app.services import ingest_service, integration_service

router = APIRouter(prefix="/ingest", tags=["ingest"])


def _check_idempotency_key(value: str | None) -> str | None:
    if value is None:
        return None
    if not 1 <= len(value) <= 128 or not value.isprintable():
        raise AppError("VALIDATION_ERROR", "Idempotency-Key must be 1-128 printable characters.", 422)
    return value


@router.post("/webhook", response_model=IngestResult, summary="Ingest one alert (generic JSON webhook)")
def webhook(
    event: IngestEvent,
    response: Response,
    integration: str | None = Query(default=None, description="Optional integration ID to attribute this event to"),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal: Principal = Depends(require("ingest:write")),
    session: Session = Depends(get_session),
) -> IngestResult:
    """Authenticate with `Authorization: Bearer tiq_...` (an API key with the `ingest:write` scope).

    Returns 201 for a new alert, 200 for a duplicate/update. Safe to retry: repeating the same event is a no-op.
    """
    ratelimit.enforce(f"ingest:{principal.organization_id}", get_settings().rate_limit_ingest_per_minute)
    linked = integration_service.get(session, principal.organization_id, integration) if integration else None
    result = ingest_service.ingest_event(
        session, principal.organization_id, event, principal.actor_type, principal.actor_id,
        integration_id=linked.id if linked else None, idempotency_key=_check_idempotency_key(idempotency_key),
    )
    if linked is not None:
        linked.last_sync_at = linked.last_success_at = utcnow()
        linked.last_error = None
        session.add(linked)
        session.commit()
    response.status_code = 201 if result.outcome == "created" else 200
    return result


@router.post("/webhook/batch", response_model=BatchIngestAccepted, status_code=202, summary="Ingest many alerts asynchronously")
def webhook_batch(
    batch: IngestBatch,
    integration: str | None = Query(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal: Principal = Depends(require("ingest:write")),
    session: Session = Depends(get_session),
) -> BatchIngestAccepted:
    ratelimit.enforce(f"ingest:{principal.organization_id}", get_settings().rate_limit_ingest_per_minute)
    linked = integration_service.get(session, principal.organization_id, integration) if integration else None
    job = jobs.enqueue(
        session, principal.organization_id, "bulk_ingest",
        payload={"events": [e.model_dump(mode="json") for e in batch.events], "actor_id": principal.actor_id,
                 "integration_id": linked.id if linked else None},
        created_by=principal.user_id, idempotency_key=_check_idempotency_key(idempotency_key),
    )
    return BatchIngestAccepted(job_id=job.id, accepted=len(batch.events))
