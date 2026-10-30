from datetime import timedelta

from fastapi import Depends, Request
from sqlmodel import Session, select

from app import ratelimit
from app.auth.principal import Principal
from app.config import get_settings
from app.database import get_session
from app.errors import AppError
from app.models import ApiKey, Membership, UserSession, utcnow
from app.security import constant_time_equals, sha256_hex, split_api_key

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
LAST_USED_WRITE_INTERVAL = timedelta(seconds=60)


def _aware(dt):
    """SQLite returns naive datetimes; storage is always UTC."""
    from datetime import timezone

    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _principal_from_api_key(session: Session, presented: str) -> Principal:
    prefix = split_api_key(presented)
    key = session.exec(select(ApiKey).where(ApiKey.prefix == prefix)).first() if prefix else None
    # Compare against a dummy hash when the key is unknown so timing does not reveal valid prefixes.
    expected = key.key_hash if key else sha256_hex("tiq_invalid")
    if not constant_time_equals(expected, sha256_hex(presented)) or key is None:
        raise AppError("UNAUTHENTICATED", "Invalid or missing credentials.", 401)
    now = utcnow()
    if key.revoked_at is not None or (key.expires_at is not None and _aware(key.expires_at) <= now):
        raise AppError("UNAUTHENTICATED", "This API key has expired or been revoked.", 401)

    # Avoid a write on every request; last_used_at is accurate to about a minute.
    if key.last_used_at is None or now - _aware(key.last_used_at) > LAST_USED_WRITE_INTERVAL:
        key.last_used_at = now
        key.use_count += 1
        session.add(key)
        session.commit()
    return Principal(
        kind="api_key",
        organization_id=key.organization_id,
        scopes=frozenset(key.scopes),
        api_key_id=key.id,
        user_id=None,
    )


def _principal_from_session(request: Request, session: Session, token: str) -> Principal:
    row = session.get(UserSession, sha256_hex(token))
    now = utcnow()
    if row is None or row.revoked_at is not None or _aware(row.expires_at) <= now:
        raise AppError("UNAUTHENTICATED", "Your session has expired. Please sign in again.", 401)

    if request.method in UNSAFE_METHODS:
        sent = request.headers.get("x-csrf-token", "")
        if not sent or not constant_time_equals(sent, row.csrf_token):
            raise AppError("CSRF_FAILED", "The request could not be verified. Reload the page and try again.", 403)

    # Role and membership are re-read on every request so removals and role changes apply at once.
    membership = session.exec(
        select(Membership).where(Membership.user_id == row.user_id, Membership.organization_id == row.organization_id)
    ).first()
    if membership is None:
        raise AppError("FORBIDDEN", "You are no longer a member of this organization.", 403)

    if now - _aware(row.last_seen_at) > timedelta(minutes=5):
        row.last_seen_at = now
        session.add(row)
        session.commit()
    return Principal(
        kind="session",
        organization_id=row.organization_id,
        user_id=row.user_id,
        role=membership.role,
        session_id=row.id,
    )


def resolve_principal(request: Request, session: Session) -> Principal:
    """Authenticate a request from an API key or session cookie. Always derived server-side."""
    settings = get_settings()
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        principal = _principal_from_api_key(session, header[7:].strip())
        limit_key = f"apikey:{principal.api_key_id}"
    else:
        token = request.cookies.get(settings.session_cookie_name)
        if not token:
            raise AppError("UNAUTHENTICATED", "Authentication is required.", 401)
        principal = _principal_from_session(request, session, token)
        limit_key = f"user:{principal.user_id}"

    ratelimit.enforce(limit_key, settings.rate_limit_api_per_minute)
    request.state.principal = principal
    return principal


def get_principal(request: Request, session: Session = Depends(get_session)) -> Principal:
    return resolve_principal(request, session)


def require(permission: str):
    """Dependency factory: authenticate, then check the permission server-side."""

    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        principal.require(permission)
        return principal

    return dependency


def client_ip(request: Request) -> str:
    # Behind a trusted proxy/ALB the first X-Forwarded-For hop is the client.
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"
