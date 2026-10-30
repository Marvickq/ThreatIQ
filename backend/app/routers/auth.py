from fastapi import APIRouter, Depends, Request, Response
from sqlmodel import Session, select

from app import ratelimit
from app.auth.deps import client_ip, get_principal
from app.auth.principal import PERMISSIONS, Principal
from app.config import get_settings
from app.database import get_session
from app.errors import AppError
from app.models import ExternalIdentity, Membership, Organization, User, UserSession
from app.schemas_saas import (
    ChangePasswordRequest,
    LoginRequest,
    MembershipOut,
    MeResponse,
    SecurityInfo,
    OrganizationOut,
    RegisterRequest,
    SessionOut,
    SwitchOrganizationRequest,
    UpdateProfileRequest,
    UserOut,
)
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_cookies(response: Response, token: str, row: UserSession) -> None:
    settings = get_settings()
    common = dict(
        max_age=settings.session_ttl_hours * 3600,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
    response.set_cookie(settings.session_cookie_name, token, httponly=True, **common)
    # Readable by the SPA so it can echo the value in X-CSRF-Token (double-submit pattern).
    response.set_cookie(settings.csrf_cookie_name, row.csrf_token, httponly=False, **common)


def _clear_cookies(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")


def build_me(session: Session, principal: Principal) -> MeResponse:
    user = session.get(User, principal.user_id)
    org = session.get(Organization, principal.organization_id)
    row = session.get(UserSession, principal.session_id)
    rows = session.exec(
        select(Membership, Organization)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(Membership.user_id == user.id)
        .order_by(Membership.created_at)
    ).all()
    settings = get_settings()
    sso_user = session.exec(select(ExternalIdentity.id).where(ExternalIdentity.user_id == user.id)).first() is not None
    return MeResponse(
        user=UserOut.model_validate(user),
        organization=OrganizationOut.model_validate(org),
        role=principal.role,
        memberships=[MembershipOut(organization_id=o.id, organization_name=o.name, role=m.role) for m, o in rows],
        csrf_token=row.csrf_token,
        capabilities=sorted(p for p in PERMISSIONS if principal.can(p)),
        demo_data_allowed=settings.allow_demo_data,
        security=SecurityInfo(
            password_min_length=settings.password_min_length, session_ttl_hours=settings.session_ttl_hours,
            login_max_failures=settings.login_max_failures, login_lockout_minutes=settings.login_lockout_minutes,
            sso_user=sso_user, sso_available=settings.entra_enabled,
        ),
    )


def _require_session_principal(principal: Principal) -> Principal:
    if principal.kind != "session":
        raise AppError("FORBIDDEN", "This action requires a signed-in user.", 403)
    return principal


@router.post("/register", response_model=MeResponse, status_code=201)
def register(body: RegisterRequest, request: Request, response: Response, session: Session = Depends(get_session)) -> MeResponse:
    ip = client_ip(request)
    ratelimit.enforce(f"register:ip:{ip}", get_settings().rate_limit_login_per_minute)
    user, org = auth_service.register(session, body.email, body.password, body.display_name, body.organization_name)
    token, row = auth_service.create_session(session, user, org.id, ip, request.headers.get("user-agent"))
    session.commit()
    _set_cookies(response, token, row)
    principal = Principal(kind="session", organization_id=org.id, user_id=user.id, role="owner", session_id=row.id)
    return build_me(session, principal)


@router.post("/login", response_model=MeResponse)
def login(body: LoginRequest, request: Request, response: Response, session: Session = Depends(get_session)) -> MeResponse:
    token, row, user = auth_service.login(session, body.email, body.password, client_ip(request), request.headers.get("user-agent"))
    _set_cookies(response, token, row)
    membership = session.exec(
        select(Membership).where(Membership.user_id == user.id, Membership.organization_id == row.organization_id)
    ).first()
    principal = Principal(kind="session", organization_id=row.organization_id, user_id=user.id, role=membership.role, session_id=row.id)
    return build_me(session, principal)


@router.post("/logout", status_code=204)
def logout(response: Response, principal: Principal = Depends(get_principal), session: Session = Depends(get_session)) -> Response:
    _require_session_principal(principal)
    auth_service.revoke_session(session, principal.session_id, principal.user_id)
    _clear_cookies(response)
    response.status_code = 204
    return response


@router.get("/me", response_model=MeResponse)
def me(principal: Principal = Depends(get_principal), session: Session = Depends(get_session)) -> MeResponse:
    return build_me(session, _require_session_principal(principal))


@router.patch("/me", response_model=MeResponse)
def update_me(body: UpdateProfileRequest, principal: Principal = Depends(get_principal), session: Session = Depends(get_session)) -> MeResponse:
    _require_session_principal(principal)
    user = session.get(User, principal.user_id)
    changes = body.model_dump(exclude_unset=True)
    if "notification_prefs" in changes and changes["notification_prefs"] is not None:
        user.notification_prefs = changes.pop("notification_prefs")
    else:
        changes.pop("notification_prefs", None)
    for field, value in changes.items():
        # locale and timezone may be cleared (null = follow the organization default); the name may not.
        if value is not None or field in ("locale", "timezone"):
            setattr(user, field, value)
    session.add(user)
    session.commit()
    return build_me(session, principal)


@router.post("/switch-organization", response_model=MeResponse)
def switch_organization(
    body: SwitchOrganizationRequest, principal: Principal = Depends(get_principal), session: Session = Depends(get_session)
) -> MeResponse:
    _require_session_principal(principal)
    row = session.get(UserSession, principal.session_id)
    auth_service.switch_organization(session, row, body.organization_id)
    membership = session.exec(
        select(Membership).where(Membership.user_id == principal.user_id, Membership.organization_id == body.organization_id)
    ).first()
    return build_me(
        session,
        Principal(kind="session", organization_id=body.organization_id, user_id=principal.user_id, role=membership.role, session_id=row.id),
    )


@router.post("/change-password", status_code=204)
def change_password(
    body: ChangePasswordRequest, principal: Principal = Depends(get_principal), session: Session = Depends(get_session)
) -> Response:
    _require_session_principal(principal)
    ratelimit.enforce(f"pwchange:{principal.user_id}", 5)
    auth_service.change_password(session, session.get(User, principal.user_id), body.current_password, body.new_password, principal.session_id)
    return Response(status_code=204)


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions(principal: Principal = Depends(get_principal), session: Session = Depends(get_session)) -> list[SessionOut]:
    _require_session_principal(principal)
    from app.models import utcnow

    rows = session.exec(
        select(UserSession)
        .where(UserSession.user_id == principal.user_id, UserSession.revoked_at.is_(None))
        .order_by(UserSession.created_at.desc())
    ).all()
    now = utcnow().replace(tzinfo=None)
    return [
        SessionOut(
            id=r.id, created_at=r.created_at, last_seen_at=r.last_seen_at, expires_at=r.expires_at, ip=r.ip,
            user_agent=r.user_agent, current=r.id == principal.session_id,
        )
        for r in rows
        if r.expires_at.replace(tzinfo=None) > now
    ]


@router.delete("/sessions/{session_id}", status_code=204)
def revoke_session(session_id: str, principal: Principal = Depends(get_principal), session: Session = Depends(get_session)) -> Response:
    _require_session_principal(principal)
    if not auth_service.revoke_session(session, session_id, principal.user_id):
        raise AppError("NOT_FOUND", "Session not found.", 404)
    return Response(status_code=204)
