"""Microsoft Entra ID sign-in: authorization-code flow with PKCE, validated on the backend.

The backend is the OAuth client (MSAL `ConfidentialClientApplication`). The browser only ever sees redirects;
no Microsoft token reaches it, and none is stored (the MSAL token cache is disabled). MSAL 1.38+ does not
validate ID tokens, so `validate_id_token` verifies the signature, issuer, audience, lifetime and nonce here.

Trust boundary: a user may only enter the organization whose `entra_tenant_id` equals the token's `tid`
(set by an operator). Identities are matched on (tid, oid), never on email.
"""
import logging
import secrets
import time
from functools import lru_cache

import jwt
import msal
from jwt import PyJWKClient
from sqlmodel import Session, select

from app.config import get_settings
from app.models import ROLES, ExternalIdentity, Membership, Organization, User, utcnow
from app.security import hash_password, sha256_hex
from app.services.audit_service import record_event

logger = logging.getLogger(__name__)

PROVIDER = "entra"
SCOPES = ["email"]  # MSAL reserves and adds openid, profile and offline_access itself (the refresh token is discarded)
ROLE_CLAIM_PREFIX = "threatiq."


class SsoError(Exception):
    """A sign-in failure with a fixed, user-safe code (shown on the login page; never raw IdP text)."""

    def __init__(self, code: str, log: str = "") -> None:
        super().__init__(log or code)
        self.code = code


class _NoTokenCache(msal.TokenCache):
    """ThreatIQ only needs the identity. Never keep access or refresh tokens in memory."""

    def add(self, event, now=None):  # noqa: D102
        return None


@lru_cache
def _app() -> msal.ConfidentialClientApplication:
    s = get_settings()
    return msal.ConfidentialClientApplication(
        s.entra_client_id, client_credential=s.entra_client_secret, authority=s.entra_authority, token_cache=_NoTokenCache()
    )


@lru_cache
def _jwks() -> PyJWKClient:
    # Signing keys are fetched over TLS from the authority and cached; unknown key IDs trigger one refresh.
    return PyJWKClient(f"{get_settings().entra_authority}/discovery/v2.0/keys", cache_keys=True, timeout=10)


# ------------------------------------------------------------------ step 1: start
def begin() -> tuple[str, dict]:
    """Return (authorization URL, flow state). The state must be kept server-bound (encrypted cookie)."""
    s = get_settings()
    try:
        flow = _app().initiate_auth_code_flow(SCOPES, redirect_uri=s.entra_redirect_uri, response_mode="query", prompt="select_account")
    except Exception as exc:  # network or misconfiguration
        logger.error("Entra: could not start sign-in (%s)", type(exc).__name__)
        raise SsoError("failed") from exc
    return flow.pop("auth_uri"), flow


# ------------------------------------------------------------------ step 2: callback
def complete(flow: dict, query: dict[str, str]) -> dict:
    """Redeem the authorization code and return the *validated* ID-token claims."""
    if "error" in query:
        # access_denied / consent_required etc. Log the code only; error_description is untrusted text.
        logger.info("Entra returned an error", extra={"idp_error": str(query.get("error"))[:64]})
        raise SsoError("denied")
    try:
        result = _app().acquire_token_by_auth_code_flow(flow, query)  # checks state and PKCE
    except ValueError as exc:  # state mismatch (CSRF) or malformed response
        raise SsoError("failed", "state mismatch") from exc
    except Exception as exc:
        logger.error("Entra: token redemption failed (%s)", type(exc).__name__)
        raise SsoError("failed") from exc
    if "error" in result or not result.get("id_token"):
        logger.warning("Entra: token endpoint error: %s", str(result.get("error"))[:64])
        raise SsoError("failed")
    return validate_id_token(result["id_token"], flow)


def validate_id_token(id_token: str, flow: dict) -> dict:
    s = get_settings()
    try:
        key = _jwks().get_signing_key_from_jwt(id_token).key
        claims = jwt.decode(
            id_token, key, algorithms=["RS256"], audience=s.entra_client_id, leeway=120,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise SsoError("failed", f"id_token rejected: {type(exc).__name__}") from exc

    tid, oid = str(claims.get("tid", "")).lower(), str(claims.get("oid", "")).lower()
    if not tid or not oid:
        raise SsoError("failed", "id_token has no tid/oid")
    # The issuer embeds the tenant. The signature already proved Microsoft issued the token.
    if claims["iss"] != f"{s.entra_authority_host.rstrip('/')}/{tid}/v2.0":
        raise SsoError("failed", "unexpected issuer")
    if not s.entra_multi_tenant and tid != s.entra_tenant_id.lower():
        raise SsoError("tenant_not_allowed", "tid is not the configured tenant")
    # MSAL sends sha256(nonce) in the request; the token must echo exactly that (replay protection).
    if not flow.get("nonce") or claims.get("nonce") != sha256_hex(flow["nonce"]):
        raise SsoError("failed", "nonce mismatch")
    claims["tid"], claims["oid"] = tid, oid
    return claims


# ------------------------------------------------------------------ step 3: map to organization, user, role
def _roles_from_claims(claims: dict) -> list[str]:
    found = []
    for raw in claims.get("roles") or []:
        value = str(raw).strip().lower().removeprefix(ROLE_CLAIM_PREFIX)
        if value in ROLES:
            found.append(value)
    return found


def _highest(roles: list[str]) -> str | None:
    return max(roles, key=ROLES.index) if roles else None


def _email(claims: dict) -> str | None:
    for candidate in (claims.get("email"), claims.get("preferred_username")):
        if isinstance(candidate, str) and "@" in candidate and len(candidate) <= 254:
            return candidate.strip().lower()
    return None


def sign_in(session: Session, claims: dict) -> tuple[User, Organization]:
    """Resolve validated claims to (user, organization), provisioning or updating the role as configured.

    Does not commit the sign-in itself; the caller creates the session and commits once.
    """
    s = get_settings()
    tid, oid = claims["tid"], claims["oid"]

    org = session.exec(select(Organization).where(Organization.entra_tenant_id == tid)).first()
    if org is None:
        # Tenant isolation: an unbound tenant gets nothing, not even a new organization.
        raise SsoError("tenant_not_allowed", f"no organization is bound to tenant {tid}")

    wanted_role = _highest(_roles_from_claims(claims))
    identity = session.exec(
        select(ExternalIdentity).where(ExternalIdentity.provider == PROVIDER, ExternalIdentity.tenant_id == tid, ExternalIdentity.subject == oid)
    ).first()

    if identity is not None:
        user = session.get(User, identity.user_id)
        if user is None or not user.is_active:
            raise SsoError("disabled", "user inactive")
        membership = session.exec(select(Membership).where(Membership.user_id == user.id, Membership.organization_id == org.id)).first()
        if membership is None:
            # An administrator removed this person; signing in again must not silently restore access.
            raise SsoError("not_member", "identity has no membership")
        if wanted_role and wanted_role != membership.role:
            _change_role(session, org, user, membership, wanted_role)
    else:
        if not s.entra_auto_provision:
            raise SsoError("not_provisioned", "auto provisioning is off")
        email = _email(claims)
        if email is None:
            raise SsoError("no_email", "token has no usable email")
        if session.exec(select(User).where(User.email == email)).first():
            # Never attach an SSO identity to an existing account by email (account-takeover vector).
            raise SsoError("conflict", "email belongs to an existing local account")
        user = User(
            email=email,
            display_name=(claims.get("name") or email.split("@")[0])[:100],
            password_hash=hash_password(secrets.token_urlsafe(32)),  # unknown to everyone: password sign-in stays impossible
        )
        session.add(user)
        session.flush()
        identity = ExternalIdentity(user_id=user.id, provider=PROVIDER, tenant_id=tid, subject=oid)
        session.add(identity)
        role = wanted_role or s.entra_default_role
        session.add(Membership(organization_id=org.id, user_id=user.id, role=role))
        record_event(session, org.id, None, "organization_member_added", "system", user.id, {"user_id": user.id, "role": role, "via": "entra"})

    now = utcnow()
    identity.last_login_at = now
    user.last_login_at = now
    session.add_all([identity, user])
    record_event(session, org.id, None, "auth_login", "human", user.id, {"via": "entra"})
    return user, org


def _change_role(session: Session, org: Organization, user: User, membership: Membership, role: str) -> None:
    if membership.role == "owner":
        owners = session.exec(select(Membership).where(Membership.organization_id == org.id, Membership.role == "owner")).all()
        if len(owners) <= 1:
            logger.warning("Entra role sync skipped: would remove the last owner", extra={"organization_id": org.id})
            return
    record_event(session, org.id, None, "organization_member_role_changed", "system", user.id,
                 {"user_id": user.id, "from": membership.role, "to": role, "via": "entra"})
    membership.role = role
    session.add(membership)


def expired(started_at: float, max_age: int = 600) -> bool:
    return time.time() - started_at > max_age
