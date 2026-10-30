import logging
import threading
import time
from typing import Callable

from sqlmodel import Session, func, select

from app.ai import prompts
from app.ai.embedding_client import EmbeddingClient
from app.ai.nebius_client import ModelError, NebiusClient
from app.ai.response_parser import AssessmentOutput, InvalidModelOutput, parse_assessment
from app.config import get_settings
from app.errors import AppError
from app.events import bus
from app.jobs import RetryableError
from app.models import Assessment, Job, utcnow
from app.observability import AI_INFERENCE, AI_LATENCY
from app.services import evidence_service
from app.services.alert_service import get_alert
from app.services.audit_service import record_event

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 2  # one retry, only for invalid model output
Progress = Callable[[int, str], None]

_semaphore: threading.BoundedSemaphore | None = None
_semaphore_lock = threading.Lock()


def _ai_slot() -> threading.BoundedSemaphore:
    """Limits concurrent model calls across all jobs in this process."""
    global _semaphore
    with _semaphore_lock:
        if _semaphore is None:
            _semaphore = threading.BoundedSemaphore(get_settings().ai_concurrency)
        return _semaphore


def active_analysis_job(session: Session, organization_id: str, alert_id: str) -> Job | None:
    """An analysis already queued/running for this alert, so double-clicks do not start two."""
    return session.exec(
        select(Job).where(
            Job.organization_id == organization_id, Job.kind == "analyze", Job.subject_id == alert_id,
            Job.status.in_(["queued", "running"]),
        )
    ).first()


def active_alert_job(session: Session, organization_id: str, alert_id: str, kinds: tuple[str, ...]) -> Job | None:
    """A queued/running job of one of these kinds for the alert (analysis already gathers evidence)."""
    return session.exec(
        select(Job).where(
            Job.organization_id == organization_id, Job.kind.in_(kinds), Job.subject_id == alert_id,
            Job.status.in_(["queued", "running"]),
        )
    ).first()


def _record_failure(session: Session, organization_id: str, alert_id: str, code: str, model: str) -> None:
    # Store the error code only; never the prompt, response body or credentials.
    record_event(session, organization_id, alert_id, "assessment_failed", "ai", model or None, {"error_code": code})
    session.commit()


def analyze_alert(
    session: Session,
    organization_id: str,
    alert_id: str,
    client: NebiusClient,
    requested_by: str | None = None,
    progress: Progress | None = None,
    embedding_client: EmbeddingClient | None = None,
) -> Assessment:
    """Gather evidence, call the real model, validate the output, persist the assessment.

    Never fabricates a result: on failure an error is raised and audited.
    """
    report = progress or (lambda _p, _m: None)
    alert = get_alert(session, organization_id, alert_id)

    if not client.is_configured:
        raise AppError(
            "MODEL_NOT_CONFIGURED", "The AI model is not configured. Set the NEBIUS_* values in backend/.env.local.", 503,
        )

    record_event(session, organization_id, alert_id, "assessment_started", "system", requested_by)
    session.commit()

    # 1. Evidence first. Provider trouble limits the evidence; it does not block the analysis.
    report(10, "Collecting evidence")
    try:
        evidence_service.enrich(session, alert, progress=lambda p, m: report(min(p, 45), m))
    except RetryableError as exc:
        logger.warning("Enrichment incomplete before analysis: %s", exc)
    report(50, "Preparing evidence package")
    package, valid_refs, items = evidence_service.build_evidence_package(
        session, alert, embedding_client if embedding_client is not None else EmbeddingClient(get_settings())
    )
    retrieval = package.get("retrieval")
    if retrieval:
        # Counts and mode only; never alert text or vectors.
        record_event(session, organization_id, alert_id, "retrieval_completed", "system", requested_by,
                     {"mode": retrieval["mode"], "candidates": retrieval["candidates"], "limitations": len(retrieval["limitations"]),
                      "cases_supplied": len(package["historical_cases"])})
        session.commit()
    user_message = prompts.build_user_message(package)

    # 2. Model call, bounded by a concurrency limit, with one retry on invalid output.
    output: AssessmentOutput | None = None
    model_name = ""
    last_error: AppError | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        report(55 + 15 * (attempt - 1), "Waiting for the model" if attempt == 1 else "Retrying after invalid output")
        started = time.perf_counter()
        try:
            with _ai_slot():
                report(60, "Generating assessment")
                response = client.complete_json(prompts.SYSTEM_PROMPT, user_message, "security_assessment", prompts.ASSESSMENT_SCHEMA)
            AI_LATENCY.observe(time.perf_counter() - started)
            model_name = response.model
            output = parse_assessment(response.content, valid_refs)
            AI_INFERENCE.labels("ok").inc()
            break
        except ModelError as exc:
            AI_INFERENCE.labels(exc.code.lower()).inc()
            last_error = AppError(exc.code, exc.message, exc.status_code)
            if exc.code != "INVALID_MODEL_OUTPUT":
                break  # provider outage / auth / rate limit: let the analyst retry
        except InvalidModelOutput as exc:
            AI_INFERENCE.labels("invalid_output").inc()
            logger.warning("Invalid model output on attempt %s: %s", attempt, exc)
            last_error = AppError("INVALID_MODEL_OUTPUT", "The model returned an assessment that failed validation. Please retry.", 502)

    if output is None:
        assert last_error is not None
        _record_failure(session, organization_id, alert_id, last_error.code, model_name)
        raise last_error

    # 3. Persist with everything needed to explain it later.
    report(90, "Saving assessment")
    version = session.exec(
        select(func.count()).select_from(Assessment).where(Assessment.alert_id == alert_id, Assessment.organization_id == organization_id)
    ).one() + 1
    assessment = Assessment(
        organization_id=organization_id,
        alert_id=alert_id,
        model_name=model_name,
        suggested_classification=output.suggested_classification,
        summary=output.summary,
        observed_facts=output.observed_facts,
        interpretation=output.interpretation or None,
        evidence=[e.model_dump() for e in output.supporting_evidence],
        missing_information=output.missing_information,
        recommended_steps=output.recommended_steps,
        version=version,
        prompt_version=prompts.PROMPT_VERSION,
        model_params=client.params(),
        evidence_ids=[
            {"id": i.id, "source_type": i.source_type, "source_id": i.source_id, "provider_status": i.provider_status, "content_hash": i.content_hash}
            for i in items
        ],
    )
    try:
        session.add(assessment)
        session.flush()
        record_event(
            session, organization_id, alert_id, "assessment_completed", "ai", model_name,
            {"assessment_id": assessment.id, "suggested_classification": assessment.suggested_classification, "version": version},
        )
        # Only a fresh alert moves to awaiting_review; never reopen a human-resolved one.
        if alert.status == "new":
            alert.status = "awaiting_review"
            alert.updated_at = utcnow()
            session.add(alert)
            record_event(session, organization_id, alert_id, "status_changed", "system", details={"from": "new", "to": "awaiting_review"})
        session.commit()
    except Exception:
        session.rollback()
        raise AppError("PERSISTENCE_ERROR", "The assessment could not be saved.", 500)

    session.refresh(assessment)
    bus.publish(organization_id, "alert.updated", {"id": alert_id, "reason": "assessment_completed"})
    return assessment
