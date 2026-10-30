from fastapi import APIRouter, Depends, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import func, text
from sqlmodel import Session, select

from app.auth.deps import require
from app.auth.principal import Principal
from app.config import get_settings
from app.database import get_session
from app.errors import AppError
from app.migrations import schema_status
from app.models import Job, Organization
from app.observability import QUEUE_DEPTH, registry
from app.security import constant_time_equals

router = APIRouter(tags=["system"])

VERSION = "2.0.0"


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness: the process is up. Does not touch dependencies."""
    return {"status": "ok"}


@router.get("/ready")
def ready(session: Session = Depends(get_session)) -> dict:
    """Readiness: the database is reachable. Redis is optional and reported separately."""
    try:
        session.exec(text("SELECT 1")).one()
    except Exception:
        raise AppError("NOT_READY", "The database is not reachable.", 503)
    return {"status": "ready", "database": "ok"}


@router.get("/metrics", include_in_schema=False)
def metrics(request: Request, session: Session = Depends(get_session)) -> Response:
    settings = get_settings()
    token = settings.metrics_token
    if not token and settings.is_production:
        # Closed by default in production: metrics expose route names, volumes and error rates.
        raise AppError("NOT_FOUND", "Not found.", 404)
    if token:
        presented = request.headers.get("authorization", "")
        if not presented.lower().startswith("bearer ") or not constant_time_equals(presented[7:].strip(), token):
            raise AppError("UNAUTHENTICATED", "A metrics token is required.", 401)
    for status, n in session.exec(select(Job.status, func.count()).where(Job.status.in_(["queued", "running"])).group_by(Job.status)).all():
        QUEUE_DEPTH.labels(status).set(n)
    return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)


@router.get("/system/status")
def system_status(principal: Principal = Depends(require("org:manage")), session: Session = Depends(get_session)) -> dict:
    """Operational status for organization admins. Reports configuration state, never secret values."""
    settings = get_settings()
    redis_state = "not_configured"
    if settings.redis_url:
        try:
            import redis

            redis.Redis.from_url(settings.redis_url, socket_timeout=1, socket_connect_timeout=1).ping()
            redis_state = "ok"
        except Exception:
            redis_state = "unreachable"
    queued = session.exec(select(func.count()).select_from(Job).where(Job.status == "queued", Job.organization_id == principal.organization_id)).one()
    running = session.exec(select(func.count()).select_from(Job).where(Job.status == "running", Job.organization_id == principal.organization_id)).one()
    # A live probe, not a config echo: if this query fails the database is reported unreachable.
    try:
        session.exec(text("SELECT 1")).one()
        schema = schema_status(session.connection())
        database = {"engine": "sqlite" if settings.database_url.startswith("sqlite") else "postgresql", "reachable": True, **schema}
    except Exception:
        database = {"engine": "sqlite" if settings.database_url.startswith("sqlite") else "postgresql", "reachable": False, "revision": None, "head": None, "up_to_date": False}
    org = session.get(Organization, principal.organization_id)
    return {
        "version": VERSION,
        "environment": settings.app_env,
        "database": database,
        "sso": {"entra_configured": settings.entra_enabled, "organization_bound": bool(org and org.entra_tenant_id)},
        "redis": redis_state,
        "artifact_storage": "s3" if settings.s3_bucket else "database",
        "ai": {"configured": bool(settings.nebius_api_key and settings.nebius_base_url and settings.nebius_model), "model": settings.nebius_model or None},
        "jobs": {"queued": queued, "running": running, "workers": settings.job_workers,
                 "backend": "celery" if settings.effective_broker_url else "in_process"},
        "sentry": bool(settings.sentry_dsn),
        "opentelemetry": bool(settings.otel_exporter_otlp_endpoint),
    }
