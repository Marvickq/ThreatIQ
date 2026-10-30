"""Job handlers. Importing this module registers them with `app.jobs`."""
import logging
from sqlmodel import Session

from app.ai.nebius_client import NebiusClient
from app.config import get_settings
from app.database import engine
from app.errors import AppError
from app.ingest.adapters import ADAPTERS, AdapterError
from app.intel import providers
from app.jobs import JobContext, JobFailed, RetryableError, handler
from app.models import utcnow
from app.schemas_saas import IngestEvent
from app.security import decrypt_json
from app.services import evidence_service, ingest_service, integration_service, investigation_service
from app.services.alert_service import get_alert
from app.services.audit_service import record_event

logger = logging.getLogger(__name__)

MAX_PAGES_PER_SYNC = 10


def _audit_auto(session: Session, ctx: JobContext, event_type: str, details: dict) -> None:
    # IDs, codes and counts only; never alert content.
    record_event(session, ctx.organization_id, ctx.subject_id, event_type, "system", None, {"job_id": ctx.job_id, **details})
    session.commit()


@handler("analyze")
def analyze(ctx: JobContext) -> dict:
    auto = bool(ctx.payload.get("auto"))  # queued by automatic triage rather than by an analyst
    with Session(engine) as session:
        if auto:
            _audit_auto(session, ctx, "auto_triage_started", {})
        try:
            assessment = investigation_service.analyze_alert(
                session, ctx.organization_id, ctx.subject_id, NebiusClient(get_settings()), ctx.created_by, ctx.progress
            )
        except AppError as exc:
            # Provider outages are the analyst's to retry; they are not auto-retried (cost, and the
            # failure is already audited).
            if auto:
                _audit_auto(session, ctx, "auto_triage_failed", {"stage": "analysis", "error_code": exc.code})
            raise JobFailed(exc.message) from exc
        except Exception as exc:
            if auto:
                session.rollback()
                _audit_auto(session, ctx, "auto_triage_failed", {"stage": "analysis", "error_type": type(exc).__name__})
            raise
        if auto:
            _audit_auto(session, ctx, "auto_triage_completed",
                        {"assessment_id": assessment.id, "suggested_classification": assessment.suggested_classification})
        return {"assessment_id": assessment.id, "suggested_classification": assessment.suggested_classification}


@handler("enrich")
def enrich(ctx: JobContext) -> dict:
    with Session(engine) as session:
        alert = get_alert(session, ctx.organization_id, ctx.subject_id)
        items = evidence_service.enrich(session, alert, force=bool(ctx.payload.get("force")), progress=ctx.progress)
        record_event(session, ctx.organization_id, alert.id, "enrichment_completed", "system", ctx.created_by,
                     {"items": len(items), "providers": sorted({i.source_type for i in items})})
        session.commit()
        return {"items": len(items), "found": sum(1 for i in items if i.provider_status == "found"),
                "not_found": sum(1 for i in items if i.provider_status == "not_found"),
                "errors": sum(1 for i in items if i.provider_status == "error")}


@handler("refresh_intel")
def refresh_intel(ctx: JobContext) -> dict:
    ctx.progress(20, "Downloading the CISA KEV catalog")
    try:
        info = providers.refresh_kev(force=True)
    except providers.ProviderError as exc:
        raise RetryableError(str(exc)) from exc
    return {"cisa_kev": {"entries": info["count"], "catalog_version": info["version"], "fetched_at": str(info["fetched_at"])}}


@handler("bulk_ingest")
def bulk_ingest(ctx: JobContext) -> dict:
    events = ctx.payload.get("events", [])
    counts = {"created": 0, "duplicate": 0, "updated": 0, "out_of_order": 0, "invalid": 0}
    with Session(engine) as session:
        for n, raw in enumerate(events, start=1):
            try:
                result = ingest_service.ingest_event(
                    session, ctx.organization_id, IngestEvent.model_validate(raw), "system", ctx.payload.get("actor_id"),
                    integration_id=ctx.payload.get("integration_id"),
                )
                counts[result.outcome] += 1
            except ValueError:
                session.rollback()
                counts["invalid"] += 1
            if n % 25 == 0:
                ctx.progress(int(90 * n / max(1, len(events))), f"Processed {n} of {len(events)}")
    return counts


@handler("sync")
def sync(ctx: JobContext) -> dict:
    with Session(engine) as session:
        integration = integration_service.get(session, ctx.organization_id, ctx.subject_id)
        if not integration.enabled:
            raise JobFailed("This integration is disabled.")
        if integration_service.compute_status(integration) == "unconfigured":
            raise JobFailed("This integration is not configured. Set the endpoint and credentials.")
        adapter = ADAPTERS[integration.kind]
        credentials = decrypt_json(integration.secret_encrypted)
        totals = {"fetched": 0, "created": 0, "updated": 0, "duplicate": 0, "out_of_order": 0, "skipped": 0}
        integration.last_sync_at = utcnow()
        session.add(integration)
        session.commit()

        try:
            for page in range(MAX_PAGES_PER_SYNC):
                ctx.progress(10 + page * 8, f"Fetching page {page + 1} from {integration.kind}")
                result = adapter.fetch(integration.config, credentials, integration.checkpoint)
                totals["fetched"] += len(result.events)
                totals["skipped"] += result.skipped
                for event in result.events:
                    outcome = ingest_service.ingest_event(
                        session, ctx.organization_id, event, "system", f"integration:{integration.id}", integration_id=integration.id
                    )
                    totals[outcome.outcome] += 1
                integration.checkpoint = result.checkpoint
                session.add(integration)
                session.commit()  # checkpoint is saved per page so an interruption resumes, not restarts
                if not result.full_page:
                    break
        except AdapterError as exc:
            integration.last_error = str(exc)[:500]
            session.add(integration)
            session.commit()
            raise JobFailed(str(exc)) from exc
        except RetryableError as exc:
            integration.last_error = str(exc)[:500]
            session.add(integration)
            session.commit()
            raise

        integration.last_success_at = utcnow()
        integration.last_error = None
        integration.status = integration_service.compute_status(integration)
        session.add(integration)
        record_event(session, ctx.organization_id, None, "integration_synced", "system", f"integration:{integration.id}", totals)
        session.commit()
        return totals
