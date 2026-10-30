from datetime import timedelta

from sqlalchemy import func
from sqlmodel import Session, select

from app.auth.principal import API_KEY_SCOPES, Principal, role_rank
from app.errors import AppError
from app.models import ApiKey, Membership, Organization, User, utcnow
from app.schemas_saas import AddMemberRequest, CreateApiKeyRequest, MemberOut, UpdateOrganizationRequest
from app.security import generate_api_key
from app.services.audit_service import record_event


def get_organization(session: Session, organization_id: str) -> Organization:
    org = session.get(Organization, organization_id)
    if org is None:
        raise AppError("NOT_FOUND", "Organization not found.", 404)
    return org


def update_organization(session: Session, principal: Principal, body: UpdateOrganizationRequest) -> Organization:
    org = get_organization(session, principal.organization_id)
    changes = body.model_dump(exclude_unset=True)
    for field, value in changes.items():
        if value is not None:
            setattr(org, field, value)
    session.add(org)
    record_event(session, org.id, None, "organization_updated", "human", principal.actor_id, {"fields": sorted(changes)})
    session.commit()
    return org


def list_members(session: Session, organization_id: str) -> list[MemberOut]:
    rows = session.exec(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.organization_id == organization_id)
        .order_by(Membership.created_at)
    ).all()
    return [
        MemberOut(
            user_id=u.id, email=u.email, display_name=u.display_name, role=m.role,
            joined_at=m.created_at, last_login_at=u.last_login_at,
        )
        for m, u in rows
    ]


def _owner_count(session: Session, organization_id: str) -> int:
    return session.exec(
        select(func.count()).select_from(Membership).where(Membership.organization_id == organization_id, Membership.role == "owner")
    ).one()


def _check_can_grant(principal: Principal, role: str) -> None:
    # Only owners can create or demote owners; admins cannot grant more than they hold.
    if role_rank(role) > role_rank(principal.role or ""):
        raise AppError("FORBIDDEN", "You cannot grant a role higher than your own.", 403)


def add_member(session: Session, principal: Principal, body: AddMemberRequest) -> MemberOut:
    _check_can_grant(principal, body.role)
    # Invitations by email are not available (no email delivery configured); the person must
    # already have registered an account.
    user = session.exec(select(User).where(User.email == body.email.lower())).first()
    if user is None:
        raise AppError("USER_NOT_FOUND", "No account exists for that email. Ask them to register first.", 404)
    existing = session.exec(
        select(Membership).where(Membership.organization_id == principal.organization_id, Membership.user_id == user.id)
    ).first()
    if existing:
        raise AppError("ALREADY_MEMBER", "That user is already a member of this organization.", 409)
    session.add(Membership(organization_id=principal.organization_id, user_id=user.id, role=body.role))
    record_event(session, principal.organization_id, None, "organization_member_added", "human", principal.actor_id,
                 {"user_id": user.id, "role": body.role})
    session.commit()
    return next(m for m in list_members(session, principal.organization_id) if m.user_id == user.id)


def _get_membership(session: Session, organization_id: str, user_id: str) -> Membership:
    membership = session.exec(
        select(Membership).where(Membership.organization_id == organization_id, Membership.user_id == user_id)
    ).first()
    if membership is None:
        raise AppError("NOT_FOUND", "Member not found.", 404)
    return membership


def update_member_role(session: Session, principal: Principal, user_id: str, role: str) -> MemberOut:
    membership = _get_membership(session, principal.organization_id, user_id)
    _check_can_grant(principal, role)
    _check_can_grant(principal, membership.role)  # admins cannot demote owners
    if membership.role == "owner" and role != "owner" and _owner_count(session, principal.organization_id) <= 1:
        raise AppError("LAST_OWNER", "An organization must keep at least one owner.", 409)
    previous = membership.role
    membership.role = role
    session.add(membership)
    record_event(session, principal.organization_id, None, "organization_member_role_changed", "human", principal.actor_id,
                 {"user_id": user_id, "from": previous, "to": role})
    session.commit()
    return next(m for m in list_members(session, principal.organization_id) if m.user_id == user_id)


def remove_member(session: Session, principal: Principal, user_id: str) -> None:
    membership = _get_membership(session, principal.organization_id, user_id)
    _check_can_grant(principal, membership.role)
    if membership.role == "owner" and _owner_count(session, principal.organization_id) <= 1:
        raise AppError("LAST_OWNER", "An organization must keep at least one owner.", 409)
    session.delete(membership)
    record_event(session, principal.organization_id, None, "organization_member_removed", "human", principal.actor_id, {"user_id": user_id})
    session.commit()


# ------------------------------------------------------------------ API keys
def create_api_key(session: Session, principal: Principal, body: CreateApiKeyRequest) -> tuple[ApiKey, str]:
    if any(s not in API_KEY_SCOPES for s in body.scopes):
        raise AppError("VALIDATION_ERROR", "Unknown scope.", 422)
    full, prefix, key_hash = generate_api_key()
    key = ApiKey(
        organization_id=principal.organization_id,
        name=body.name.strip(),
        prefix=prefix,
        key_hash=key_hash,
        scopes=sorted(set(body.scopes)),
        created_by=principal.user_id,
        expires_at=utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None,
    )
    session.add(key)
    record_event(session, principal.organization_id, None, "api_key_created", "human", principal.actor_id,
                 {"prefix": prefix, "scopes": key.scopes, "name": key.name})
    session.commit()
    session.refresh(key)
    return key, full


def rotate_api_key(session: Session, principal: Principal, key_id: str) -> tuple[ApiKey, str]:
    """Issue a replacement with the same name, scopes and lifetime, and revoke the old key in one transaction."""
    old = session.get(ApiKey, key_id)
    if old is None or old.organization_id != principal.organization_id:
        raise AppError("NOT_FOUND", "API key not found.", 404)
    now = utcnow()
    expires = old.expires_at.replace(tzinfo=None) if old.expires_at else None
    if old.revoked_at is not None or (expires and expires <= now.replace(tzinfo=None)):
        raise AppError("KEY_INACTIVE", "Only an active key can be rotated. Create a new key instead.", 409)
    lifetime = (expires - old.created_at.replace(tzinfo=None)) if expires else None
    full, prefix, key_hash = generate_api_key()
    new = ApiKey(
        organization_id=principal.organization_id, name=old.name, prefix=prefix, key_hash=key_hash, scopes=list(old.scopes),
        created_by=principal.user_id, expires_at=now + lifetime if lifetime else None,
    )
    old.revoked_at = now
    session.add(old)
    session.add(new)
    record_event(session, principal.organization_id, None, "api_key_rotated", "human", principal.actor_id,
                 {"old_prefix": old.prefix, "new_prefix": prefix, "scopes": new.scopes})
    session.commit()
    session.refresh(new)
    return new, full


def list_api_keys(session: Session, organization_id: str) -> list[ApiKey]:
    return list(session.exec(select(ApiKey).where(ApiKey.organization_id == organization_id).order_by(ApiKey.created_at.desc())).all())


def revoke_api_key(session: Session, principal: Principal, key_id: str) -> ApiKey:
    key = session.get(ApiKey, key_id)
    if key is None or key.organization_id != principal.organization_id:
        raise AppError("NOT_FOUND", "API key not found.", 404)
    if key.revoked_at is None:
        key.revoked_at = utcnow()
        session.add(key)
        record_event(session, principal.organization_id, None, "api_key_revoked", "human", principal.actor_id, {"prefix": key.prefix})
        session.commit()
    return key
