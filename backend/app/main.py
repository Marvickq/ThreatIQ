import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import jobs, models, scheduler  # noqa: F401  (models registers tables with SQLModel metadata)
from app import job_handlers  # noqa: F401  (registers background job handlers)
from app.events import bus
from app.config import get_settings
from app.database import engine
from app.errors import register_error_handlers
from app.migrations import run_migrations
from app.observability import RequestContextMiddleware, configure_logging, init_error_tracking
from app.routers import alerts, auth, dashboard, events, ingest, integrations, investigations, organization, reports, sso, system

logger = logging.getLogger("threatiq")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    run_migrations(engine)
    bus.start(asyncio.get_running_loop())
    jobs.start_workers()
    scheduler.start()
    logger.info("ThreatIQ started", extra={"environment": get_settings().app_env})
    try:
        yield
    finally:
        # Graceful shutdown: stop scheduling, let running jobs finish, then close the event bus.
        logger.info("ThreatIQ shutting down")
        scheduler.stop()
        jobs.stop_workers()
        bus.stop()


def create_app() -> FastAPI:
    settings = get_settings()  # validates configuration at startup; production misconfiguration fails fast
    configure_logging(settings)

    app = FastAPI(
        title="ThreatIQ API",
        version="2.0.0",
        description="Multi-tenant cybersecurity alert investigation. All routes are under /api/v1.",
        lifespan=lifespan,
        docs_url="/api/v1/docs",
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID", "Idempotency-Key", "Authorization"],
        expose_headers=["X-Request-ID", "Retry-After"],
    )
    app.add_middleware(RequestContextMiddleware, settings=settings)
    register_error_handlers(app)
    init_error_tracking(app, settings)

    api = APIRouter(prefix="/api/v1")
    for module in (system, auth, sso, organization, dashboard, alerts, investigations, reports, ingest, integrations, events):
        api.include_router(module.router)
    app.include_router(api)
    return app


app = create_app()
