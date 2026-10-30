import logging
import re
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlmodel import Session, select

from app import ratelimit
from app.config import get_settings
from app.errors import AppError
from app.models import Membership, Organization, User, UserSession, utcnow
from app.security import (
    DUMMY_PASSWORD_HASH,
    hash_password,
    new_token,
    password_needs_rehash,
    sha256_hex,
    verify_password,
)
from app.services.audit_service import record_event

logger = logging.getLogger(__name__)


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def validate_password(password: str, email: str) -> None:
    settings = get_settings()
    if len(password) < settings.password_min_length:
        raise AppError("WEAK_PASSWORD", f"Password must be at least {settings.password_min_length} characters.", 422)
    if len(password) > 256:
        raise AppError("WEAK_PASSWORD", "Password is too long.", 422)
    if password.lower() == email.lower() or password.lower() in {"password123", "1234567890", "qwertyuiop"}:
        raise AppError("WEAK_PASSWORD", "Choose a less guessable password.", 422)


def _slugify(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "org"
    return f"{base}-{secrets.token_hex(3)}"


def register(session: Session, email: str, password: str, display_name: str, organization_name: str) -> tuple[User, Organization]:
    settings = get_settings()
    email = email.strip().lower()
    user_count = session.exec(select(func.count()).select_from(User)).one()
    if not settings.registration_enabled and user_count > 0:
        raise AppError("REGISTRATION_DISABLED", "Registration is disabled on this instance.", 403)
    validate_password(password, email)
    if session.exec(select(User).where(User.email == email)).first():
        raise AppError("EMAIL_TAKEN", "An account with this email already exists.", 409)

    user = User(email=email, password_hash=hash_password(password), display_name=display_name)
    session.add(user)
    session.flush()

    # The very first user adopts a pre-existing, ownerless organization (data migrated from the
    # single-tenant version of ThreatIQ) instead of leaving that data orphaned.
    org = None
    if user_count == 0:
        candidates = session.exec(select(Organization)).all()
        if len(candidates) == 1 and not session.exec(select(Membership).where(Membership.organization_id == candidates[0].id)).first():
            org = candidates[0]
            org.name = organization_name
            session.add(org)
    if org is None:
        org = Organization(
            name=organization_name,
            slug=_slugify(organization_name),
            default_locale=settings.default_locale,
            default_timezone=settings.default_timezone,
        )
        session.add(org)
        session.flush()

    session.add(Membership(organization_id=org.id, user_id=user.id, role="owner"))
    record_event(session, org.id, None, "organization_member_added", "human", user.id, {"user_id": user.id, "role": "owner", "via": "registration"})
    session.commit()
    return user, org


def _active_memberships(session: Session, user_id: str) -> list[Membership]:
    return list(session.exec(select(Membership).where(Membership.user_id == user_id).order_by(Membership.created_at)).all())


def create_session(session: Session, user: User, organization_id: str, ip: str | None, user_agent: str | None) -> tuple[str, UserSession]:
    settings = get_settings()
    token = new_token(32)
    now = utcnow()
    row = UserSession(
        id=sha256_hex(token),
        user_id=user.id,
        organization_id=organization_id,
        csrf_token=new_token(24),
        ip=ip,
        user_agent=(user_agent or "")[:300] or None,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=settings.session_ttl_hours),
    )
    session.add(row)
    return token, row


def login(session: Session, email: str, password: str, ip: str, user_agent: str | None) -> tuple[str, UserSession, User]:
    settings = get_settings()
    email = email.strip().lower()
    # Abuse controls: per-IP and per-account throttling, plus a temporary account lockout.
    ratelimit.enforce(f"login:ip:{ip}", settings.rate_limit_login_per_minute)
    ratelimit.enforce(f"login:email:{sha256_hex(email)[:32]}", settings.rate_limit_login_per_minute)

    user = session.exec(select(User).where(User.email == email)).first()
    now = utcnow()
    if user is not None and user.locked_until is not None and _aware(user.locked_until) > now:
        verify_password(DUMMY_PASSWORD_HASH, password)
        raise AppError("ACCOUNT_LOCKED", "Too many failed attempts. Try again later.", 429)

    valid = verify_password(user.password_hash if user else DUMMY_PASSWORD_HASH, password)
    if user is None or not valid or not user.is_active:
        if user is not None and user.is_active:
            user.failed_logins += 1
            if user.failed_logins >= settings.login_max_failures:
                user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
                user.failed_logins = 0
                logger.warning("Account locked after repeated failed logins", extra={"user_id": user.id})
            session.add(user)
            session.commit()
        logger.info("Failed login", extra={"ip": ip})
        raise AppError("INVALID_CREDENTIALS", "Invalid email or password.", 401)

    memberships = _active_memberships(session, user.id)
    if not memberships:
        raise AppError("NO_ORGANIZATION", "Your account does not belong to any organization.", 403)

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    session.add(user)
    token, row = create_session(session, user, memberships[0].organization_id, ip, user_agent)
    record_event(session, memberships[0].organization_id, None, "auth_login", "human", user.id, {"ip": ip})
    session.commit()
    return token, row, user


def revoke_session(session: Session, session_id: str, user_id: str) -> bool:
    row = session.get(UserSession, session_id)
    if row is None or row.user_id != user_id or row.revoked_at is not None:
        return False
    row.revoked_at = utcnow()
    session.add(row)
    session.commit()
    return True


def switch_organization(session: Session, row: UserSession, organization_id: str) -> None:
    membership = session.exec(
        select(Membership).where(Membership.user_id == row.user_id, Membership.organization_id == organization_id)
    ).first()
    if membership is None:
        raise AppError("FORBIDDEN", "You are not a member of that organization.", 403)
    row.organization_id = organization_id
    session.add(row)
    session.commit()


def change_password(session: Session, user: User, current: str, new: str, keep_session_id: str | None) -> None:
    if not verify_password(user.password_hash, current):
        raise AppError("INVALID_CREDENTIALS", "Current password is incorrect.", 401)
    validate_password(new, user.email)
    user.password_hash = hash_password(new)
    session.add(user)
    # Sign out every other device.
    others = session.exec(
        select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
    ).all()
    now = utcnow()
    for other in others:
        if other.id != keep_session_id:
            other.revoked_at = now
            session.add(other)
    for membership in _active_memberships(session, user.id):
        record_event(session, membership.organization_id, None, "auth_password_changed", "human", user.id)
    session.commit()
