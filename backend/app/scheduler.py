"""Lightweight in-process scheduler for provider polling and catalog refresh.

Multiple API instances are safe: each poll is enqueued with an idempotency key derived from the
integration and the current time bucket, so only one job per interval is created. For larger
deployments run a dedicated scheduler process (`python -m app.scheduler`) and disable it in the API
with SCHEDULER_ENABLED=false.
"""
import logging
import threading
import time

from sqlmodel import Session, select

from app import jobs
from app.config import get_settings
from app.database import engine
from app.intel import providers
from app.models import Integration, utcnow
from app.services import integration_service

logger = logging.getLogger(__name__)

TICK_SECONDS = 30
_stop = threading.Event()
_thread: threading.Thread | None = None


def _aware(dt):
    from datetime import timezone

    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def tick() -> int:
    """Enqueue sync jobs for integrations that are due. Returns how many were enqueued."""
    enqueued = 0
    now = utcnow()
    with Session(engine) as session:
        for integration in session.exec(select(Integration).where(Integration.enabled.is_(True))).all():
            if integration.kind not in integration_service.PULL_KINDS or integration_service.compute_status(integration) == "unconfigured":
                continue
            interval = int(integration.config.get("poll_interval_seconds", 300))
            last = _aware(integration.last_sync_at)
            if last is not None and (now - last).total_seconds() < interval:
                continue
            bucket = int(now.timestamp() // interval)
            jobs.enqueue(session, integration.organization_id, "sync", subject_id=integration.id, idempotency_key=f"sync:{integration.id}:{bucket}")
            enqueued += 1
    return enqueued


def _loop() -> None:
    while not _stop.wait(TICK_SECONDS):
        try:
            tick()
            providers.refresh_kev()  # no-op until the cached catalog is older than KEV_TTL_HOURS
        except providers.ProviderError as exc:
            logger.warning("Scheduled KEV refresh failed: %s", exc)
        except Exception:
            logger.exception("Scheduler tick failed")


def start() -> None:
    global _thread
    if not getattr(get_settings(), "scheduler_enabled", True):
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="scheduler", daemon=True)
    _thread.start()


def stop() -> None:
    _stop.set()
    if _thread is not None:
        _thread.join(timeout=5)


if __name__ == "__main__":  # dedicated scheduler process
    from app.job_handlers import *  # noqa: F401,F403  (registers handlers)
    from app.observability import configure_logging

    configure_logging(get_settings())
    logger.info("Scheduler process started")
    jobs.start_workers()
    try:
        while True:
            tick()
            time.sleep(TICK_SECONDS)
    except KeyboardInterrupt:
        jobs.stop_workers()
