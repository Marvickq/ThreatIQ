from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy import func
from sqlmodel import Session, select

from app.auth.deps import get_principal, require
from app.auth.principal import Principal
from app.config import get_settings
from app.database import get_session
from app.errors import AppError
from app.models import Assessment, AuditEvent, Notification, Organization, ReviewDecision, SecurityAlert, User, utcnow
from app.services.audit_service import record_event
from app.schemas_saas import (
    AddMemberRequest,
    ApiKeyCreated,
    ApiKeyOut,
    CreateApiKeyRequest,
    MemberOut,
    NotificationOut,
    OrganizationOut,
    UpdateMemberRequest,
    UpdateOrganizationRequest,
)
from app.services import org_service
from app.services.seed_service import seed_demo_alerts

router = APIRouter(tags=["organization"])


@router.get("/organization", response_model=OrganizationOut)
def get_org(principal: Principal = Depends(require("alerts:read")), session: Session = Depends(get_session)) -> OrganizationOut:
    return OrganizationOut.model_validate(org_service.get_organization(session, principal.organization_id))


@router.patch("/organization", response_model=OrganizationOut)
def update_org(
    body: UpdateOrganizationRequest, principal: Principal = Depends(require("org:manage")), session: Session = Depends(get_session)
) -> OrganizationOut:
    return OrganizationOut.model_validate(org_service.update_organization(session, principal, body))


@router.get("/organization/members", response_model=list[MemberOut])
def members(principal: Principal = Depends(require("members:manage")), session: Session = Depends(get_session)) -> list[MemberOut]:
    return org_service.list_members(session, principal.organization_id)


@router.post("/organization/members", response_model=MemberOut, status_code=201)
def add_member(body: AddMemberRequest, principal: Principal = Depends(require("members:manage")), session: Session = Depends(get_session)) -> MemberOut:
    return org_service.add_member(session, principal, body)


@router.patch("/organization/members/{user_id}", response_model=MemberOut)
def update_member(
    user_id: str, body: UpdateMemberRequest, principal: Principal = Depends(require("members:manage")), session: Session = Depends(get_session)
) -> MemberOut:
    return org_service.update_member_role(session, principal, user_id, body.role)


@router.delete("/organization/members/{user_id}", status_code=204)
def remove_member(user_id: str, principal: Principal = Depends(require("members:manage")), session: Session = Depends(get_session)) -> Response:
    org_service.remove_member(session, principal, user_id)
    return Response(status_code=204)


@router.post("/organization/demo-data", status_code=201)
def load_demo_data(principal: Principal = Depends(require("org:manage")), session: Session = Depends(get_session)) -> dict:
    """Load clearly labelled synthetic alerts into this organization. Disabled unless ALLOW_DEMO_DATA=true."""
    if not get_settings().allow_demo_data:
        raise AppError("DEMO_DATA_DISABLED", "Demo data is disabled on this instance.", 403)
    created = seed_demo_alerts(session, principal.organization_id)
    return {"created": created}


# ------------------------------------------------------------------ API keys
@router.get("/api-keys", response_model=list[ApiKeyOut])
def list_keys(principal: Principal = Depends(require("apikeys:manage")), session: Session = Depends(get_session)) -> list[ApiKeyOut]:
    return [ApiKeyOut.model_validate(k) for k in org_service.list_api_keys(session, principal.organization_id)]


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=201)
def create_key(body: CreateApiKeyRequest, principal: Principal = Depends(require("apikeys:manage")), session: Session = Depends(get_session)) -> ApiKeyCreated:
    key, full = org_service.create_api_key(session, principal, body)
    return ApiKeyCreated(**ApiKeyOut.model_validate(key).model_dump(), key=full)


@router.post("/api-keys/{key_id}/rotate", response_model=ApiKeyCreated, status_code=201)
def rotate_key(key_id: str, principal: Principal = Depends(require("apikeys:manage")), session: Session = Depends(get_session)) -> ApiKeyCreated:
    key, full = org_service.rotate_api_key(session, principal, key_id)
    return ApiKeyCreated(**ApiKeyOut.model_validate(key).model_dump(), key=full)


@router.delete("/api-keys/{key_id}", response_model=ApiKeyOut)
def revoke_key(key_id: str, principal: Principal = Depends(require("apikeys:manage")), session: Session = Depends(get_session)) -> ApiKeyOut:
    return ApiKeyOut.model_validate(org_service.revoke_api_key(session, principal, key_id))


# ------------------------------------------------------------------ organization audit log
@router.get("/audit-events")
def audit_events(
    principal: Principal = Depends(require("org:manage")),
    session: Session = Depends(get_session),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    event_type: str | None = Query(None, max_length=64),
    since: datetime | None = Query(None, description="Only events at or after this time (naive values are UTC)"),
    until: datetime | None = Query(None, description="Only events before this time (naive values are UTC)"),
) -> dict:
    """Read-only. There is deliberately no route that creates, edits or deletes audit events."""
    conditions = [AuditEvent.organization_id == principal.organization_id]
    if event_type:
        conditions.append(AuditEvent.event_type == event_type)
    if since:
        conditions.append(AuditEvent.created_at >= (since if since.tzinfo else since.replace(tzinfo=timezone.utc)))
    if until:
        conditions.append(AuditEvent.created_at < (until if until.tzinfo else until.replace(tzinfo=timezone.utc)))
    total = session.exec(select(func.count()).select_from(AuditEvent).where(*conditions)).one()
    rows = session.exec(
        select(AuditEvent).where(*conditions).order_by(AuditEvent.created_at.desc()).limit(limit).offset(offset)
    ).all()
    user_ids = {e.actor_id for e in rows if e.actor_type == "human" and e.actor_id}
    names = dict(session.exec(select(User.id, User.display_name).where(User.id.in_(user_ids))).all()) if user_ids else {}
    event_types = session.exec(
        select(AuditEvent.event_type).where(AuditEvent.organization_id == principal.organization_id).distinct().order_by(AuditEvent.event_type)
    ).all()
    return {
        "total": total,
        "event_types": list(event_types),
        "items": [
            {"id": e.id, "event_type": e.event_type, "actor_type": e.actor_type, "actor_id": e.actor_id,
             "actor_name": names.get(e.actor_id) if e.actor_type == "human" else ("API key" if (e.actor_id or "").startswith("api_key:") else None),
             "alert_id": e.alert_id, "details": e.details, "created_at": e.created_at}
            for e in rows
        ],
    }


# ------------------------------------------------------------------ notifications (in-app)
@router.get("/notifications", response_model=list[NotificationOut])
def notifications(
    principal: Principal = Depends(get_principal), session: Session = Depends(get_session), unread_only: bool = False
) -> list[NotificationOut]:
    if principal.kind != "session":
        raise AppError("FORBIDDEN", "Notifications belong to signed-in users.", 403)
    q = select(Notification).where(Notification.user_id == principal.user_id, Notification.organization_id == principal.organization_id)
    if unread_only:
        q = q.where(Notification.read_at.is_(None))
    return [NotificationOut.model_validate(n) for n in session.exec(q.order_by(Notification.created_at.desc()).limit(50)).all()]


@router.post("/notifications/read-all", status_code=204)
def read_all(principal: Principal = Depends(get_principal), session: Session = Depends(get_session)) -> Response:
    from app.models import utcnow

    if principal.kind != "session":
        raise AppError("FORBIDDEN", "Notifications belong to signed-in users.", 403)
    for n in session.exec(
        select(Notification).where(Notification.user_id == principal.user_id, Notification.read_at.is_(None))
    ).all():
        n.read_at = utcnow()
        session.add(n)
    session.commit()
    return Response(status_code=204)


# ------------------------------------------------------------------ data export and retention (non-destructive)
@router.get("/organization/export", summary="Download this organization's investigation data as JSON")
def export_data(principal: Principal = Depends(require("data:export")), session: Session = Depends(get_session)) -> JSONResponse:
    """Alerts, assessments, human decisions and audit events. Credentials and API key hashes are never included.

    The export itself is audited. Large organizations should export in the background; this endpoint is bounded.
    """
    org = principal.organization_id
    limit = 20_000
    alerts = session.exec(select(SecurityAlert).where(SecurityAlert.organization_id == org).order_by(SecurityAlert.created_at).limit(limit)).all()
    payload = {
        "exported_at": utcnow(),
        "organization_id": org,
        "truncated": len(alerts) >= limit,
        "alerts": [a.model_dump() for a in alerts],
        "assessments": [a.model_dump() for a in session.exec(select(Assessment).where(Assessment.organization_id == org).limit(limit)).all()],
        "decisions": [d.model_dump() for d in session.exec(select(ReviewDecision).where(ReviewDecision.organization_id == org).limit(limit)).all()],
        "audit_events": [e.model_dump() for e in session.exec(select(AuditEvent).where(AuditEvent.organization_id == org).order_by(AuditEvent.created_at).limit(limit * 2)).all()],
    }
    record_event(session, org, None, "data_exported", "human", principal.actor_id, {"alerts": len(alerts)})
    session.commit()
    return JSONResponse(
        content=jsonable_encoder(payload),
        headers={"Content-Disposition": 'attachment; filename="threatiq-export.json"'},
    )


@router.get("/organization/retention", summary="How many resolved alerts exceed the retention policy")
def retention_preview(principal: Principal = Depends(require("org:manage")), session: Session = Depends(get_session)) -> dict:
    """Reports only. ThreatIQ never deletes security records automatically, and no deletion workflow exists yet."""
    org = session.get(Organization, principal.organization_id)
    if org.retention_days <= 0:
        return {"retention_days": 0, "eligible_resolved_alerts": 0, "note": "Retention is unlimited."}
    cutoff = utcnow() - timedelta(days=org.retention_days)
    n = session.exec(
        select(func.count()).select_from(SecurityAlert).where(
            SecurityAlert.organization_id == principal.organization_id, SecurityAlert.status == "resolved", SecurityAlert.updated_at < cutoff
        )
    ).one()
    return {
        "retention_days": org.retention_days,
        "eligible_resolved_alerts": n,
        "note": "Informational. Nothing is deleted automatically; export first, then archive according to your policy.",
    }
