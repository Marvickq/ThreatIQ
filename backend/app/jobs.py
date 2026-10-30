"""Persistent background jobs.

The `jobs` table is the source of truth for status, progress and errors. Execution happens either
in a Celery worker (when a broker is configured) or on an in-process thread pool (local
development / single-node). Both paths run the same handler through `run_job`, which is
idempotent: a job that is not `queued` is never started twice.
"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Callable

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.config import get_settings
from app.database import engine
from app.events import bus
from app.models import Job, Notification, User, utcnow
from app.observability import JOBS, redact

logger = logging.getLogger(__name__)

Handler = Callable[["JobContext"], dict]
HANDLERS: dict[str, Handler] = {}


class RetryableError(Exception):
    """A recoverable failure (rate limit, timeout, 5xx). The job is retried with exponential backoff."""

    def __init__(self, message: str, delay_seconds: float | None = None) -> None:
        super().__init__(message)
        self.delay_seconds = delay_seconds


class JobFailed(Exception):
    """A non-recoverable failure with a message that is safe to show to users."""


def handler(kind: str):
    def register(fn: Handler) -> Handler:
        HANDLERS[kind] = fn
        return fn

    return register


class JobContext:
    def __init__(self, job_id: str) -> None:
        with Session(engine) as session:
            job = session.get(Job, job_id)
            self.job_id = job.id
            self.organization_id = job.organization_id
            self.kind = job.kind
            self.payload = dict(job.payload)
            self.subject_id = job.subject_id
            self.created_by = job.created_by
            self.attempts = job.attempts

    def progress(self, percent: int, message: str) -> None:
        with Session(engine) as session:
            job = session.get(Job, self.job_id)
            job.progress = max(0, min(99, percent))
            job.message = message[:300]
            session.add(job)
            session.commit()
            _publish(job)


def _publish(job: Job) -> None:
    bus.publish(
        job.organization_id,
        "job.updated",
        {"id": job.id, "kind": job.kind, "status": job.status, "progress": job.progress, "message": job.message,
         "subject_id": job.subject_id, "error": job.error},
    )


# --------------------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------------------

_executor: ThreadPoolExecutor | None = None
_timers: set[threading.Timer] = set()
_shutting_down = False


def start_workers() -> None:
    global _executor, _shutting_down
    _shutting_down = False
    if not get_settings().effective_broker_url:
        _executor = ThreadPoolExecutor(max_workers=get_settings().job_workers, thread_name_prefix="job")
    recover_interrupted_jobs()


def stop_workers() -> None:
    """Graceful shutdown: stop accepting delayed retries and let running jobs finish."""
    global _shutting_down
    _shutting_down = True
    for timer in list(_timers):
        timer.cancel()
    if _executor is not None:
        _executor.shutdown(wait=True, cancel_futures=False)


def _dispatch(job_id: str, countdown: float = 0) -> None:
    if _shutting_down:
        return  # stays 'queued' in the database and is picked up by recovery on next start
    if countdown > 0:
        timer = threading.Timer(countdown, lambda: (_timers.discard(timer), _dispatch(job_id)))
        timer.daemon = True
        _timers.add(timer)
        timer.start()
        return
    settings = get_settings()
    if settings.effective_broker_url:  # pragma: no cover - requires a broker
        from app.worker import celery_app

        celery_app.send_task("threatiq.run_job", args=[job_id])
    elif _executor is not None:
        _executor.submit(run_job, job_id)
    else:
        logger.error("No job executor is running; job %s stays queued", job_id)


def enqueue(
    session: Session,
    organization_id: str,
    kind: str,
    payload: dict | None = None,
    created_by: str | None = None,
    subject_id: str | None = None,
    idempotency_key: str | None = None,
) -> Job:
    """Create a job and dispatch it. With an idempotency key, repeating the call returns the same job."""
    if idempotency_key:
        existing = session.exec(
            select(Job).where(Job.organization_id == organization_id, Job.idempotency_key == idempotency_key)
        ).first()
        if existing is not None:
            return existing
    job = Job(
        organization_id=organization_id, kind=kind, payload=payload or {}, created_by=created_by,
        subject_id=subject_id, idempotency_key=idempotency_key, message="Queued",
    )
    session.add(job)
    try:
        session.commit()
    except IntegrityError:  # lost an idempotency race
        session.rollback()
        return session.exec(
            select(Job).where(Job.organization_id == organization_id, Job.idempotency_key == idempotency_key)
        ).one()
    session.refresh(job)
    _publish(job)
    _dispatch(job.id)
    return job


def retry(session: Session, job: Job) -> Job:
    if job.status not in ("failed", "cancelled"):
        return job
    job.status, job.error, job.progress, job.message = "queued", None, 0, "Queued for retry"
    job.attempts = 0
    job.idempotency_key = None  # a manual retry is a new attempt
    session.add(job)
    session.commit()
    _publish(job)
    _dispatch(job.id)
    return job


# --------------------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------------------


def run_job(job_id: str) -> None:
    settings = get_settings()
    with Session(engine) as session:
        job = session.get(Job, job_id)
        if job is None or job.status != "queued":
            return  # already running, finished, or cancelled
        job.status = "running"
        job.attempts += 1
        job.started_at = job.started_at or utcnow()
        job.message = "Running"
        session.add(job)
        session.commit()
        _publish(job)
        kind, attempts = job.kind, job.attempts

    fn = HANDLERS.get(kind)
    outcome, result, error, retry_delay = "failed", {}, None, None
    try:
        if fn is None:
            raise JobFailed(f"No handler registered for job kind '{kind}'.")
        result = fn(JobContext(job_id)) or {}
        outcome = "succeeded"
    except RetryableError as exc:
        error = redact(str(exc))[:500]
        if attempts < settings.job_max_attempts:
            outcome = "retry"
            retry_delay = exc.delay_seconds if exc.delay_seconds is not None else min(300, 5 * (2 ** (attempts - 1)))
    except JobFailed as exc:
        error = redact(str(exc))[:500]
    except Exception as exc:
        logger.exception("Job crashed", extra={"job_id": job_id, "kind": kind})
        error = f"Unexpected error ({type(exc).__name__}). See server logs."

    with Session(engine) as session:
        job = session.get(Job, job_id)
        job.error = error
        if outcome == "retry":
            job.status, job.message = "queued", f"Retrying in {int(retry_delay)}s (attempt {attempts + 1})"
        elif outcome == "succeeded":
            job.status, job.progress, job.message, job.result, job.finished_at = "succeeded", 100, "Done", result, utcnow()
        else:
            job.status, job.message, job.finished_at = "failed", error or "Failed", utcnow()
        session.add(job)
        if outcome == "failed" and job.created_by:
            _notify_failure(session, job)
        session.commit()
        _publish(job)
    JOBS.labels(kind, "retry" if outcome == "retry" else outcome).inc()
    if outcome == "retry":
        _dispatch(job_id, countdown=retry_delay)


def _notify_failure(session: Session, job: Job) -> None:
    user = session.get(User, job.created_by)
    if user is None or not user.notification_prefs.get("on_job_failure", True) or not user.notification_prefs.get("in_app", True):
        return
    session.add(
        Notification(
            organization_id=job.organization_id, user_id=user.id, kind="job_failed",
            title=f"{job.kind.replace('_', ' ').title()} failed", body=job.error, severity="medium",
            link=f"/alerts/{job.subject_id}" if job.subject_id and job.kind in ("analyze", "enrich") else None,
        )
    )


def recover_interrupted_jobs() -> None:
    """After a crash or restart: re-run jobs that were queued; fail (or requeue) jobs left running."""
    settings = get_settings()
    stale_cutoff = utcnow() - timedelta(seconds=1)
    with Session(engine) as session:
        for job in session.exec(select(Job).where(Job.status == "running")).all():
            if job.attempts < settings.job_max_attempts:
                job.status, job.message = "queued", "Requeued after an interruption"
            else:
                job.status, job.error, job.message, job.finished_at = "failed", "Interrupted by a restart.", "Interrupted", utcnow()
            session.add(job)
        session.commit()
        queued = [j.id for j in session.exec(select(Job).where(Job.status == "queued", Job.created_at < stale_cutoff)).all()]
    for job_id in queued:
        _dispatch(job_id)
    if queued:
        logger.info("Recovered queued jobs", extra={"count": len(queued)})
