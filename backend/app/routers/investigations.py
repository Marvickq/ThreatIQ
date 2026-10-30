from fastapi import APIRouter, Depends, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy import func
from sqlmodel import Session, select

from app import jobs, ratelimit
from app.ai.nebius_client import NebiusClient
from app.auth.deps import require
from app.auth.principal import Principal
from app.config import get_settings
from app.database import get_session
from app.errors import AppError
from app.models import Job, Organization
from app.schemas import AssessmentOut
from app.schemas_saas import EvidenceList, EvidenceOut, IndicatorOut, JobList, JobOut, ProviderStatus
from app.services import alert_service, evidence_service, indicators, investigation_service

router = APIRouter(tags=["investigations"])


def get_model_client() -> NebiusClient:
    return NebiusClient(get_settings())


@router.post("/alerts/{alert_id}/analyze", status_code=202, response_model=None)
def analyze(
    alert_id: str,
    sync: bool = Query(default=False, description="Run inline and return the assessment (201) instead of a job (202)"),
    principal: Principal = Depends(require("alerts:write")),
    session: Session = Depends(get_session),
    client: NebiusClient = Depends(get_model_client),
):
    alert = alert_service.get_alert(session, principal.organization_id, alert_id)
    if not client.is_configured:
        raise AppError("MODEL_NOT_CONFIGURED", "The AI model is not configured. Set the NEBIUS_* values in backend/.env.local.", 503)
    ratelimit.enforce(f"ai:{principal.organization_id}", get_settings().rate_limit_ai_per_hour, 3600)

    if sync:
        assessment = investigation_service.analyze_alert(session, principal.organization_id, alert.id, client, principal.user_id)
        return JSONResponse(status_code=201, content=jsonable_encoder(AssessmentOut.model_validate(assessment, from_attributes=True)))

    existing = investigation_service.active_analysis_job(session, principal.organization_id, alert.id)
    job = existing or jobs.enqueue(session, principal.organization_id, "analyze", subject_id=alert.id, created_by=principal.user_id)
    return JSONResponse(status_code=202, content=jsonable_encoder(JobOut.model_validate(job)))


@router.post("/alerts/{alert_id}/enrich", response_model=JobOut, status_code=202)
def enrich(
    alert_id: str,
    force: bool = False,
    principal: Principal = Depends(require("alerts:write")),
    session: Session = Depends(get_session),
) -> JobOut:
    alert = alert_service.get_alert(session, principal.organization_id, alert_id)
    if not force:
        # An analysis (manual or automatic triage) already enriches; do not repeat the provider lookups.
        active = investigation_service.active_alert_job(session, principal.organization_id, alert.id, ("enrich", "analyze"))
        if active is not None:
            return JobOut.model_validate(active)
    job = jobs.enqueue(session, principal.organization_id, "enrich", payload={"force": force}, subject_id=alert.id, created_by=principal.user_id)
    return JobOut.model_validate(job)


@router.get("/alerts/{alert_id}/evidence", response_model=EvidenceList)
def evidence(alert_id: str, principal: Principal = Depends(require("alerts:read")), session: Session = Depends(get_session)) -> EvidenceList:
    alert_service.get_alert(session, principal.organization_id, alert_id)
    items = []
    for e in evidence_service.list_for_alert(session, principal.organization_id, alert_id):
        out = EvidenceOut.model_validate(e)
        out.stale = evidence_service.is_stale(e)
        items.append(out)
    return EvidenceList(items=items)


@router.get("/alerts/{alert_id}/indicators", response_model=list[IndicatorOut])
def alert_indicators(alert_id: str, principal: Principal = Depends(require("alerts:read")), session: Session = Depends(get_session)) -> list[IndicatorOut]:
    alert = alert_service.get_alert(session, principal.organization_id, alert_id)
    return [IndicatorOut.model_validate(i) for i in indicators.for_alert(session, alert)]


@router.get("/intel/status", response_model=list[ProviderStatus])
def intel_status(principal: Principal = Depends(require("alerts:read")), session: Session = Depends(get_session)) -> list[ProviderStatus]:
    org = session.get(Organization, principal.organization_id)
    return [ProviderStatus(**p) for p in evidence_service.providers_status(session, org)]


@router.post("/intel/refresh", response_model=JobOut, status_code=202)
def intel_refresh(principal: Principal = Depends(require("org:manage")), session: Session = Depends(get_session)) -> JobOut:
    return JobOut.model_validate(jobs.enqueue(session, principal.organization_id, "refresh_intel", created_by=principal.user_id))


# ---------------------------------------------------------------------------------- jobs
@router.get("/jobs", response_model=JobList)
def list_jobs(
    status: str | None = Query(default=None, max_length=20),
    kind: str | None = Query(default=None, max_length=32),
    subject_id: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(require("alerts:read")),
    session: Session = Depends(get_session),
) -> JobList:
    conditions = [Job.organization_id == principal.organization_id]
    if status:
        conditions.append(Job.status == status)
    if kind:
        conditions.append(Job.kind == kind)
    if subject_id:
        conditions.append(Job.subject_id == subject_id)
    total = session.exec(select(func.count()).select_from(Job).where(*conditions)).one()
    rows = session.exec(select(Job).where(*conditions).order_by(Job.created_at.desc()).limit(limit).offset(offset)).all()
    return JobList(items=[JobOut.model_validate(j) for j in rows], total=total)


def _get_job(session: Session, principal: Principal, job_id: str) -> Job:
    job = session.get(Job, job_id)
    if job is None or job.organization_id != principal.organization_id:
        raise AppError("NOT_FOUND", "Job not found.", 404)
    return job


@router.get("/jobs/{job_id}", response_model=JobOut)
def get_job(job_id: str, principal: Principal = Depends(require("alerts:read")), session: Session = Depends(get_session)) -> JobOut:
    return JobOut.model_validate(_get_job(session, principal, job_id))


@router.post("/jobs/{job_id}/retry", response_model=JobOut, status_code=202)
def retry_job(job_id: str, principal: Principal = Depends(require("alerts:write")), session: Session = Depends(get_session)) -> JobOut:
    job = _get_job(session, principal, job_id)
    if job.status not in ("failed", "cancelled"):
        raise AppError("CONFLICT", "Only failed or cancelled jobs can be retried.", 409)
    return JobOut.model_validate(jobs.retry(session, job))
