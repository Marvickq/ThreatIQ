from sqlmodel import Session, select

from app.auth.principal import Principal
from app.errors import AppError
from app.ingest.adapters import ADAPTERS
from app.models import Integration, utcnow
from app.safe_url import validate_outbound_url
from app.schemas_saas import IntegrationCreate, IntegrationOut, IntegrationUpdate
from app.security import decrypt_json, encrypt_json
from app.services.audit_service import record_event

PULL_KINDS = set(ADAPTERS)
SAFE_CONFIG_KEYS = {"endpoint", "index", "min_level", "verify_tls", "poll_interval_seconds", "source"}


def _clean_config(kind: str, config: dict) -> dict:
    cleaned = {k: v for k, v in config.items() if k in SAFE_CONFIG_KEYS}
    if kind in PULL_KINDS:
        if cleaned.get("endpoint"):
            cleaned["endpoint"] = validate_outbound_url(str(cleaned["endpoint"]))
        interval = int(cleaned.get("poll_interval_seconds", 300))
        cleaned["poll_interval_seconds"] = max(60, min(86_400, interval))
    return cleaned


def compute_status(integration: Integration) -> str:
    """Never report 'connected' unless a sync or ingest actually succeeded."""
    if integration.kind in PULL_KINDS:
        adapter = ADAPTERS[integration.kind]
        if not all(integration.config.get(k) for k in adapter.required_config) or not integration.secret_encrypted:
            return "unconfigured"
        creds = decrypt_json(integration.secret_encrypted)
        if not all(creds.get(k) for k in adapter.required_credentials):
            return "unconfigured"
    if integration.last_error and (integration.last_success_at is None or integration.last_sync_at and integration.last_sync_at > integration.last_success_at):
        return "error"
    if integration.last_success_at:
        return "connected"
    return "awaiting_events" if integration.kind == "webhook" else "never_synced"


def to_out(integration: Integration) -> IntegrationOut:
    return IntegrationOut(
        id=integration.id, kind=integration.kind, name=integration.name, enabled=integration.enabled, config=integration.config,
        status=compute_status(integration), has_credentials=bool(integration.secret_encrypted), last_sync_at=integration.last_sync_at,
        last_success_at=integration.last_success_at, last_error=integration.last_error, created_at=integration.created_at,
    )


def get(session: Session, organization_id: str, integration_id: str) -> Integration:
    integration = session.get(Integration, integration_id)
    if integration is None or integration.organization_id != organization_id:
        raise AppError("NOT_FOUND", "Integration not found.", 404)
    return integration


def list_all(session: Session, organization_id: str) -> list[Integration]:
    return list(session.exec(select(Integration).where(Integration.organization_id == organization_id).order_by(Integration.created_at)).all())


def create(session: Session, principal: Principal, body: IntegrationCreate) -> Integration:
    if session.exec(select(Integration).where(Integration.organization_id == principal.organization_id, Integration.name == body.name)).first():
        raise AppError("CONFLICT", "An integration with that name already exists.", 409)
    integration = Integration(
        organization_id=principal.organization_id, kind=body.kind, name=body.name.strip(), enabled=body.enabled,
        config=_clean_config(body.kind, body.config),
        secret_encrypted=encrypt_json(body.credentials) if body.credentials else None,
    )
    integration.status = compute_status(integration)
    session.add(integration)
    session.flush()
    record_event(session, principal.organization_id, None, "integration_created", "human", principal.actor_id,
                 {"integration_id": integration.id, "kind": body.kind})
    session.commit()
    return integration


def update(session: Session, principal: Principal, integration_id: str, body: IntegrationUpdate) -> Integration:
    integration = get(session, principal.organization_id, integration_id)
    changed = []
    if body.name is not None:
        integration.name = body.name.strip()
        changed.append("name")
    if body.config is not None:
        integration.config = _clean_config(integration.kind, {**integration.config, **body.config})
        changed.append("config")
    if body.credentials is not None:
        # Merge so a partial update (e.g. only the password) does not wipe the other fields.
        current = decrypt_json(integration.secret_encrypted) if integration.secret_encrypted else {}
        integration.secret_encrypted = encrypt_json({**current, **body.credentials}) if (current or body.credentials) else None
        changed.append("credentials")
    if body.enabled is not None:
        integration.enabled = body.enabled
        changed.append("enabled")
    integration.updated_at = utcnow()
    integration.status = compute_status(integration)
    session.add(integration)
    record_event(session, principal.organization_id, None, "integration_updated", "human", principal.actor_id,
                 {"integration_id": integration.id, "fields": changed})  # field names only, never values
    session.commit()
    return integration


def test_connection(session: Session, principal: Principal, integration_id: str) -> dict:
    integration = get(session, principal.organization_id, integration_id)
    if integration.kind not in PULL_KINDS:
        raise AppError("NOT_SUPPORTED", "Webhook integrations receive events; there is nothing to test from here.", 422)
    if compute_status(integration) == "unconfigured":
        raise AppError("UNCONFIGURED", "Set the endpoint and credentials first.", 422)
    from app.ingest.adapters import AdapterError
    from app.jobs import RetryableError

    adapter = ADAPTERS[integration.kind]
    try:
        message = adapter.test(integration.config, decrypt_json(integration.secret_encrypted))
        return {"ok": True, "message": message}
    except AdapterError as exc:
        return {"ok": False, "message": str(exc)}
    except RetryableError as exc:
        return {"ok": False, "message": str(exc)}
