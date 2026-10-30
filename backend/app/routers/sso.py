"""Microsoft Entra ID single sign-on. Password sign-in in routers/auth.py is unchanged and keeps working."""
import logging
import time
from urllib.parse import quote

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlmodel import Session

from app import ratelimit
from app.auth.deps import client_ip
from app.config import get_settings
from app.database import get_session
from app.routers.auth import _set_cookies
from app.security import decrypt_json, encrypt_json
from app.services import auth_service, entra_service
from app.services.entra_service import SsoError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/sso", tags=["auth"])

FLOW_COOKIE = "tiq_sso"
FLOW_MAX_AGE = 600
FLOW_COOKIE_PATH = "/api/v1/auth/sso"


class SsoConfig(BaseModel):
    entra_enabled: bool


def _safe_next(value: str | None) -> str:
    # Same-site relative paths only, so the callback can never be turned into an open redirect.
    return value if value and value.startswith("/") and not value.startswith("//") and "\\" not in value and len(value) <= 512 else "/"


def _back_to_login(error: str) -> RedirectResponse:
    response = RedirectResponse(f"{get_settings().frontend_origin.rstrip('/')}/login?sso_error={quote(error)}", status_code=303)
    response.delete_cookie(FLOW_COOKIE, path=FLOW_COOKIE_PATH)
    return response


@router.get("/config", response_model=SsoConfig)
def config() -> SsoConfig:
    """Lets the sign-in page know whether to offer the Microsoft button. Reveals nothing else."""
    return SsoConfig(entra_enabled=get_settings().entra_enabled)


@router.get("/entra/login")
def entra_login(request: Request, next: str | None = Query(default=None, max_length=512)) -> RedirectResponse:
    settings = get_settings()
    if not settings.entra_enabled:
        return _back_to_login("not_configured")
    ratelimit.enforce(f"sso:ip:{client_ip(request)}", settings.rate_limit_login_per_minute)
    try:
        auth_url, flow = entra_service.begin()
    except SsoError as exc:
        return _back_to_login(exc.code)

    response = RedirectResponse(auth_url, status_code=303)
    # Binds this browser to this attempt. Encrypted because it holds the PKCE verifier; httpOnly; short-lived.
    # SameSite=Lax is required: the return from Microsoft is a cross-site top-level navigation.
    response.set_cookie(
        FLOW_COOKIE, encrypt_json({"flow": flow, "next": _safe_next(next), "t": time.time()}),
        max_age=FLOW_MAX_AGE, httponly=True, secure=settings.cookie_secure, samesite="lax", path=FLOW_COOKIE_PATH,
    )
    return response


@router.get("/entra/callback")
def entra_callback(request: Request, session: Session = Depends(get_session)) -> RedirectResponse:
    settings = get_settings()
    if not settings.entra_enabled:
        return _back_to_login("not_configured")
    ip = client_ip(request)
    ratelimit.enforce(f"sso:ip:{ip}", settings.rate_limit_login_per_minute)

    try:
        raw = request.cookies.get(FLOW_COOKIE)
        if not raw:
            raise SsoError("expired", "no flow cookie")
        try:
            saved = decrypt_json(raw)
        except ValueError as exc:
            raise SsoError("failed", "flow cookie not decryptable") from exc
        if entra_service.expired(float(saved.get("t", 0)), FLOW_MAX_AGE):
            raise SsoError("expired", "flow too old")

        claims = entra_service.complete(saved["flow"], dict(request.query_params))
        user, org = entra_service.sign_in(session, claims)
        token, row = auth_service.create_session(session, user, org.id, ip, request.headers.get("user-agent"))
        session.commit()
    except SsoError as exc:
        session.rollback()
        logger.info("Entra sign-in refused", extra={"reason": str(exc)[:200], "ip": ip})
        return _back_to_login(exc.code)
    except Exception:
        session.rollback()
        logger.exception("Entra sign-in failed unexpectedly")
        return _back_to_login("failed")

    response = RedirectResponse(f"{settings.frontend_origin.rstrip('/')}{_safe_next(saved.get('next'))}", status_code=303)
    response.delete_cookie(FLOW_COOKIE, path=FLOW_COOKIE_PATH)
    _set_cookies(response, token, row)
    return response
