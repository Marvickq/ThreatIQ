"""Operator commands (run with server access):

    python -m app.cli reset-password someone@example.com
    python -m app.cli list-users
    python -m app.cli sso-bind <organization-slug> <entra-tenant-id>
    python -m app.cli sso-unbind <organization-slug>
    python -m app.cli sso-list

`reset-password` is the account-recovery path: ThreatIQ has no email delivery, so there is no
self-service reset. It sets a random temporary password, prints it once, unlocks the account and
signs out every existing session. The action is recorded in each of the user's organizations' audit logs.
"""
import argparse
import re
import secrets
import sys

from sqlmodel import Session, select

from app.database import engine
from app.migrations import run_migrations
from app.models import Membership, Organization, User, UserSession, utcnow
from app.security import hash_password
from app.services.audit_service import record_event


def reset_password(email: str) -> int:
    run_migrations(engine)
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == email.strip().lower())).first()
        if user is None:
            print(f"No account with that email.", file=sys.stderr)
            return 1
        temporary = secrets.token_urlsafe(15)
        user.password_hash = hash_password(temporary)
        user.failed_logins = 0
        user.locked_until = None
        session.add(user)
        now = utcnow()
        for row in session.exec(select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))).all():
            row.revoked_at = now
            session.add(row)
        for membership in session.exec(select(Membership).where(Membership.user_id == user.id)).all():
            record_event(session, membership.organization_id, None, "auth_password_reset_by_operator", "system", None, {"user_id": user.id})
        session.commit()
    print(f"Temporary password for {email}: {temporary}")
    print("All sessions were signed out. Ask the user to sign in and change it immediately (Settings -> Security).")
    return 0


def list_users() -> int:
    run_migrations(engine)
    with Session(engine) as session:
        for u in session.exec(select(User).order_by(User.created_at)).all():
            print(f"{u.email}\t{u.display_name}\t{'active' if u.is_active else 'disabled'}")
    return 0


_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def sso_bind(slug: str, tenant_id: str) -> int:
    """Let users of one Entra tenant sign in to one organization. This is the tenant-isolation boundary,
    so it is an operator action, never exposed through the API."""
    tenant_id = tenant_id.strip().lower()
    if not _GUID.match(tenant_id):
        print("The tenant ID must be a GUID (Entra admin center > Overview > Tenant ID).", file=sys.stderr)
        return 1
    run_migrations(engine)
    with Session(engine) as session:
        org = session.exec(select(Organization).where(Organization.slug == slug)).first()
        if org is None:
            print("No organization with that slug. Run sso-list to see slugs.", file=sys.stderr)
            return 1
        other = session.exec(select(Organization).where(Organization.entra_tenant_id == tenant_id)).first()
        if other is not None and other.id != org.id:
            print(f"That tenant is already bound to organization {other.slug}.", file=sys.stderr)
            return 1
        previous = org.entra_tenant_id
        org.entra_tenant_id = tenant_id
        session.add(org)
        record_event(session, org.id, None, "sso_tenant_bound", "system", None, {"from": previous, "to": tenant_id})
        session.commit()
    print(f"Organization {slug} now accepts Entra sign-in from tenant {tenant_id}.")
    return 0


def sso_unbind(slug: str) -> int:
    run_migrations(engine)
    with Session(engine) as session:
        org = session.exec(select(Organization).where(Organization.slug == slug)).first()
        if org is None:
            print("No organization with that slug.", file=sys.stderr)
            return 1
        previous, org.entra_tenant_id = org.entra_tenant_id, None
        session.add(org)
        record_event(session, org.id, None, "sso_tenant_unbound", "system", None, {"from": previous})
        session.commit()
    print(f"Organization {slug} no longer accepts Entra sign-in. Existing sessions stay valid until they expire or are revoked.")
    return 0


def sso_list() -> int:
    run_migrations(engine)
    with Session(engine) as session:
        for o in session.exec(select(Organization).order_by(Organization.created_at)).all():
            print(f"{o.slug}\t{o.name}\t{o.entra_tenant_id or '-'}")
    return 0


def embed_backfill(slug: str, limit: int) -> int:
    """Embed an organization's existing alerts so they become searchable. Calls the embedding API."""
    from app.ai.embedding_client import EmbeddingClient
    from app.config import get_settings
    from app.models import SecurityAlert
    from app.services import embedding_service

    run_migrations(engine)
    with Session(engine) as session:
        org = session.exec(select(Organization).where(Organization.slug == slug)).first()
        if org is None:
            print(f"No organization with slug {slug!r}.")
            return 1
        ok, why = embedding_service.allowed(session, org.id)
        if not ok:
            print(f"Not embedding: {why}")
            return 1
        client = EmbeddingClient(get_settings())
        alerts = session.exec(
            select(SecurityAlert).where(SecurityAlert.organization_id == org.id, SecurityAlert.is_demo == False)  # noqa: E712
            .order_by(SecurityAlert.created_at.desc()).limit(limit)
        ).all()
        total = embedding_service.IndexResult()
        for start in range(0, len(alerts), 16):
            r = embedding_service.index_alerts(session, alerts[start:start + 16], client)
            total.indexed, total.unchanged, total.failed = total.indexed + r.indexed, total.unchanged + r.unchanged, total.failed + r.failed
            total.error = total.error or r.error
        print(f"indexed={total.indexed} unchanged={total.unchanged} failed={total.failed}" + (f" error={total.error}" if total.error else ""))
        return 1 if total.failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    reset = sub.add_parser("reset-password", help="Set a temporary password and sign the user out everywhere")
    reset.add_argument("email")
    sub.add_parser("list-users", help="List registered accounts")
    bind = sub.add_parser("sso-bind", help="Allow an Entra tenant to sign in to an organization")
    bind.add_argument("organization_slug")
    bind.add_argument("tenant_id")
    unbind = sub.add_parser("sso-unbind", help="Stop accepting Entra sign-in for an organization")
    unbind.add_argument("organization_slug")
    sub.add_parser("sso-list", help="List organizations and their bound Entra tenants")
    emb = sub.add_parser("embed-backfill", help="Embed an organization's real alerts for semantic retrieval")
    emb.add_argument("organization_slug")
    emb.add_argument("--limit", type=int, default=500)
    args = parser.parse_args()
    if args.command == "reset-password":
        return reset_password(args.email)
    if args.command == "sso-bind":
        return sso_bind(args.organization_slug, args.tenant_id)
    if args.command == "sso-unbind":
        return sso_unbind(args.organization_slug)
    if args.command == "sso-list":
        return sso_list()
    if args.command == "embed-backfill":
        return embed_backfill(args.organization_slug, args.limit)
    return list_users()


if __name__ == "__main__":
    raise SystemExit(main())
