"""Celery entry point. Run a worker with:

    celery -A app.worker.celery_app worker --loglevel=INFO --concurrency=2

Requires CELERY_BROKER_URL (or REDIS_URL). Not exercised in this repository's verification because
no Redis server is available there; the in-process executor runs the same handlers.
"""
import logging

from celery import Celery
from celery.signals import worker_process_init

from app import jobs
from app.config import get_settings
from app.migrations import run_migrations  # noqa: F401
from app.observability import configure_logging

settings = get_settings()
configure_logging(settings)

celery_app = Celery("threatiq", broker=settings.effective_broker_url or "memory://", backend=None)
celery_app.conf.update(
    task_acks_late=True,  # a crashed worker's task is redelivered
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_time_limit=900,
    task_soft_time_limit=840,
    broker_connection_retry_on_startup=True,
)


@worker_process_init.connect
def _init(**_kwargs) -> None:
    # Importing registers the job handlers.
    from app import job_handlers  # noqa: F401

    logging.getLogger(__name__).info("Celery worker process ready")


@celery_app.task(name="threatiq.run_job")
def run_job_task(job_id: str) -> None:
    from app import job_handlers  # noqa: F401

    jobs.run_job(job_id)
