from fastapi import APIRouter, Depends
from sqlmodel import Session

from app import jobs
from app.auth.deps import require
from app.auth.principal import Principal
from app.database import get_session
from app.schemas_saas import IntegrationCreate, IntegrationOut, IntegrationUpdate, JobOut
from app.services import integration_service

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("", response_model=list[IntegrationOut])
def list_integrations(principal: Principal = Depends(require("integrations:manage")), session: Session = Depends(get_session)) -> list[IntegrationOut]:
    return [integration_service.to_out(i) for i in integration_service.list_all(session, principal.organization_id)]


@router.post("", response_model=IntegrationOut, status_code=201)
def create_integration(body: IntegrationCreate, principal: Principal = Depends(require("integrations:manage")), session: Session = Depends(get_session)) -> IntegrationOut:
    return integration_service.to_out(integration_service.create(session, principal, body))


@router.patch("/{integration_id}", response_model=IntegrationOut)
def update_integration(
    integration_id: str, body: IntegrationUpdate, principal: Principal = Depends(require("integrations:manage")), session: Session = Depends(get_session)
) -> IntegrationOut:
    return integration_service.to_out(integration_service.update(session, principal, integration_id, body))


@router.post("/{integration_id}/test")
def test_integration(integration_id: str, principal: Principal = Depends(require("integrations:manage")), session: Session = Depends(get_session)) -> dict:
    return integration_service.test_connection(session, principal, integration_id)


@router.post("/{integration_id}/sync", response_model=JobOut, status_code=202)
def sync_now(integration_id: str, principal: Principal = Depends(require("integrations:manage")), session: Session = Depends(get_session)) -> JobOut:
    integration = integration_service.get(session, principal.organization_id, integration_id)
    job = jobs.enqueue(session, principal.organization_id, "sync", subject_id=integration.id, created_by=principal.user_id)
    return JobOut.model_validate(job)
