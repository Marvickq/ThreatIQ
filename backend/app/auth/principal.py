from dataclasses import dataclass, field

from app.errors import AppError
from app.models import ROLES

# Minimum role (for signed-in users) and API-key scope for each permission.
PERMISSIONS: dict[str, tuple[str, str | None]] = {
    "alerts:read": ("viewer", "alerts:read"),
    "alerts:write": ("analyst", "alerts:write"),  # status changes, assignment, decisions, analysis, enrichment
    "ingest:write": ("admin", "ingest:write"),
    "integrations:manage": ("admin", None),
    "apikeys:manage": ("admin", None),
    "members:manage": ("admin", None),
    "org:manage": ("admin", None),
    "org:owner": ("owner", None),
    "data:export": ("admin", None),
}

API_KEY_SCOPES = ("alerts:read", "alerts:write", "ingest:write")


def role_rank(role: str) -> int:
    return ROLES.index(role) if role in ROLES else -1


@dataclass(frozen=True)
class Principal:
    """Who is calling, and for which organization. Always derived server-side, never from the client."""

    kind: str  # "session" | "api_key"
    organization_id: str
    user_id: str | None = None
    role: str | None = None  # session principals only
    scopes: frozenset[str] = field(default_factory=frozenset)  # API-key principals only
    session_id: str | None = None
    api_key_id: str | None = None

    @property
    def actor_type(self) -> str:
        return "human" if self.kind == "session" else "system"

    @property
    def actor_id(self) -> str | None:
        return self.user_id or (f"api_key:{self.api_key_id}" if self.api_key_id else None)

    def can(self, permission: str) -> bool:
        min_role, scope = PERMISSIONS[permission]
        if self.kind == "session":
            return role_rank(self.role or "") >= role_rank(min_role)
        return scope is not None and scope in self.scopes

    def require(self, permission: str) -> None:
        if not self.can(permission):
            raise AppError("FORBIDDEN", "You do not have permission to perform this action.", 403)
