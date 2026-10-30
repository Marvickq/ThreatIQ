import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy import JSON, Column, Index, UniqueConstraint
from sqlmodel import Field, SQLModel

SEVERITIES = ("low", "medium", "high", "critical")
ALERT_STATUSES = ("new", "investigating", "awaiting_review", "resolved")
CLASSIFICATIONS = ("likely_true_positive", "likely_false_positive", "needs_review")
DECISIONS = ("true_positive", "false_positive", "needs_further_review")
ACTOR_TYPES = ("system", "ai", "human")
# Ordered lowest to highest privilege.
ROLES = ("viewer", "analyst", "admin", "owner")
INTEGRATION_KINDS = ("webhook", "wazuh", "elastic")
JOB_STATUSES = ("queued", "running", "succeeded", "failed", "cancelled")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


def _json(default=list) -> Column:
    return Column(JSON, nullable=False)


def _ts_default():
    return Field(default_factory=utcnow)


# --------------------------------------------------------------------------------------
# Identity and tenancy
# --------------------------------------------------------------------------------------


class Organization(SQLModel, table=True):
    __tablename__ = "organizations"

    id: str = Field(default_factory=new_id, primary_key=True)
    name: str
    slug: str = Field(sa_column=Column(sa.String, nullable=False, unique=True))
    default_locale: str = "en"
    default_timezone: str = "UTC"
    # Security records are kept at least this long. 0 means keep indefinitely.
    retention_days: int = 0
    # Indicators (never alert text) may be sent to third-party reputation providers only if true.
    allow_external_enrichment: bool = Field(default=False, sa_column_kwargs={"server_default": sa.false()})
    # New HIGH/CRITICAL ingested alerts are analysed automatically (advice only) if true.
    auto_triage_enabled: bool = Field(default=False, sa_column_kwargs={"server_default": sa.false()})
    # Microsoft Entra directory (tenant) whose users sign in to this organization via SSO. Set only by an
    # operator (`python -m app.cli sso-bind`), never through the API, so an organization cannot claim a tenant.
    entra_tenant_id: str | None = Field(default=None, sa_column=Column(sa.String, nullable=True, unique=True, index=True))
    created_at: datetime = _ts_default()


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: str = Field(default_factory=new_id, primary_key=True)
    email: str = Field(sa_column=Column(sa.String, nullable=False, unique=True))
    password_hash: str
    display_name: str
    locale: str | None = None
    timezone: str | None = None
    notification_prefs: dict = Field(default_factory=dict, sa_column=_json())
    is_active: bool = Field(default=True, sa_column_kwargs={"server_default": sa.true()})
    failed_logins: int = Field(default=0, sa_column_kwargs={"server_default": "0"})
    locked_until: datetime | None = None
    last_login_at: datetime | None = None
    created_at: datetime = _ts_default()


class Membership(SQLModel, table=True):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_membership_org_user"),)

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id", index=True)
    user_id: str = Field(foreign_key="users.id", index=True)
    role: str
    created_at: datetime = _ts_default()


class ExternalIdentity(SQLModel, table=True):
    """A user's identity at an external identity provider, keyed by the provider's immutable IDs.

    Sign-in matches on (provider, tenant, subject) only, never on email, because email claims are mutable
    and not proof of ownership.
    """

    __tablename__ = "external_identities"
    __table_args__ = (UniqueConstraint("provider", "tenant_id", "subject", name="uq_external_identity"),)

    id: str = Field(default_factory=new_id, primary_key=True)
    user_id: str = Field(foreign_key="users.id", index=True)
    provider: str  # "entra"
    tenant_id: str  # Entra "tid"
    subject: str  # Entra "oid"
    created_at: datetime = _ts_default()
    last_login_at: datetime | None = None


class UserSession(SQLModel, table=True):
    __tablename__ = "sessions"

    # SHA-256 of the opaque session token; the token itself is never stored.
    id: str = Field(primary_key=True)
    user_id: str = Field(foreign_key="users.id", index=True)
    organization_id: str = Field(foreign_key="organizations.id")
    csrf_token: str
    ip: str | None = None
    user_agent: str | None = None
    created_at: datetime = _ts_default()
    last_seen_at: datetime = _ts_default()
    expires_at: datetime
    revoked_at: datetime | None = None


class ApiKey(SQLModel, table=True):
    __tablename__ = "api_keys"

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id", index=True)
    name: str
    # Visible lookup prefix, e.g. "tiq_ab12cd34". The secret part is only ever shown once.
    prefix: str = Field(sa_column=Column(sa.String, nullable=False, unique=True))
    key_hash: str
    scopes: list = Field(default_factory=list, sa_column=_json())
    created_by: str | None = Field(default=None, foreign_key="users.id")
    created_at: datetime = _ts_default()
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None
    use_count: int = Field(default=0, sa_column_kwargs={"server_default": "0"})


# --------------------------------------------------------------------------------------
# Alerts and ingestion
# --------------------------------------------------------------------------------------


class Integration(SQLModel, table=True):
    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_integration_org_name"),)

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id", index=True)
    kind: str
    name: str
    enabled: bool = Field(default=True, sa_column_kwargs={"server_default": sa.true()})
    # Non-secret settings (endpoint URL, index pattern, poll interval, ...).
    config: dict = Field(default_factory=dict, sa_column=_json())
    # Fernet-encrypted JSON of credentials. Never returned by the API.
    secret_encrypted: str | None = None
    # unconfigured | connected | error | never_synced
    status: str = "unconfigured"
    last_sync_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    checkpoint: dict = Field(default_factory=dict, sa_column=_json())
    created_at: datetime = _ts_default()
    updated_at: datetime = _ts_default()


class SecurityAlert(SQLModel, table=True):
    __tablename__ = "security_alerts"
    __table_args__ = (
        Index("ix_security_alerts_severity", "severity"),
        Index("ix_security_alerts_status", "status"),
        Index("ix_security_alerts_created_at", "created_at"),
        Index("ix_security_alerts_org_created", "organization_id", "created_at"),
        Index("ix_security_alerts_org_dedup", "organization_id", "source", "external_id"),
    )

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id")
    title: str
    description: str
    severity: str
    source: str
    affected_entity: str | None = None
    status: str = "new"
    is_demo: bool = Field(default=False, sa_column_kwargs={"server_default": sa.false()})
    # Ingestion / deduplication
    integration_id: str | None = Field(default=None, foreign_key="integrations.id")
    external_id: str | None = None
    fingerprint: str | None = None
    occurrence_count: int = Field(default=1, sa_column_kwargs={"server_default": "1"})
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    assigned_to: str | None = Field(default=None, foreign_key="users.id")
    created_at: datetime = _ts_default()
    updated_at: datetime = _ts_default()


class SourceEvent(SQLModel, table=True):
    """The raw event exactly as received, preserved for audit. Treated as untrusted data."""

    __tablename__ = "source_events"
    __table_args__ = (
        UniqueConstraint("organization_id", "source", "external_id", "event_time", name="uq_source_event"),
        Index("ix_source_events_org_alert", "organization_id", "alert_id"),
    )

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id")
    alert_id: str | None = Field(default=None, foreign_key="security_alerts.id")
    integration_id: str | None = Field(default=None, foreign_key="integrations.id")
    source: str
    external_id: str
    event_time: datetime
    received_at: datetime = _ts_default()
    idempotency_key: str | None = None
    raw: dict = Field(default_factory=dict, sa_column=_json())
    # Set when the payload was large and stored via the artifact store (S3 when configured).
    raw_storage_uri: str | None = None


class AlertIndicator(SQLModel, table=True):
    __tablename__ = "alert_indicators"
    __table_args__ = (
        UniqueConstraint("alert_id", "type", "value", name="uq_alert_indicator"),
        Index("ix_alert_indicators_lookup", "organization_id", "type", "value"),
    )

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id")
    alert_id: str = Field(foreign_key="security_alerts.id", index=True)
    type: str  # cve | ip | domain | url | md5 | sha1 | sha256 | account | host
    value: str  # normalised (lower-case etc.)


# --------------------------------------------------------------------------------------
# Investigation
# --------------------------------------------------------------------------------------


class EvidenceItem(SQLModel, table=True):
    __tablename__ = "evidence_items"
    __table_args__ = (Index("ix_evidence_org_alert", "organization_id", "alert_id"),)

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id")
    alert_id: str = Field(foreign_key="security_alerts.id")
    # alert | historical_alert | cisa_kev | nvd | virustotal
    source_type: str
    source_id: str  # stable identifier the model may cite, e.g. a CVE ID or alert ID
    title: str
    url: str | None = None
    # found | not_found | error. "not_found" and "error" are recorded, never hidden.
    provider_status: str = "found"
    content: dict = Field(default_factory=dict, sa_column=_json())
    content_hash: str
    storage_uri: str | None = None
    confidence: float | None = None
    retrieved_at: datetime = _ts_default()
    expires_at: datetime | None = None


class AlertEmbedding(SQLModel, table=True):
    """A vector for one alert's normalised text. The alert row stays the source of truth.

    `embedding` is the portable copy (used by the SQLite brute-force fallback). On PostgreSQL with pgvector,
    migration 0006 also adds an `embedding_vec vector(N)` column with an HNSW index, written by embedding_service.
    """

    __tablename__ = "alert_embeddings"
    __table_args__ = (
        UniqueConstraint("alert_id", "model", name="uq_alert_embedding_alert_model"),
        Index("ix_alert_embeddings_org_model", "organization_id", "model"),
    )

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id")
    alert_id: str = Field(foreign_key="security_alerts.id")
    model: str
    dimensions: int
    # Hash of the exact text embedded, so unchanged alerts are never re-embedded.
    text_hash: str
    embedding: list = Field(default_factory=list, sa_column=_json())
    created_at: datetime = _ts_default()


class Assessment(SQLModel, table=True):
    __tablename__ = "assessments"
    __table_args__ = (Index("ix_assessments_alert_created", "alert_id", "created_at"),)

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id")
    alert_id: str = Field(foreign_key="security_alerts.id")
    model_name: str
    suggested_classification: str
    summary: str
    observed_facts: list = Field(default_factory=list, sa_column=_json())
    interpretation: str | None = None
    evidence: list = Field(default_factory=list, sa_column=_json())
    missing_information: list = Field(default_factory=list, sa_column=_json())
    recommended_steps: list = Field(default_factory=list, sa_column=_json())
    confidence: float | None = None
    # Everything needed to explain this assessment later.
    version: int = Field(default=1, sa_column_kwargs={"server_default": "1"})
    prompt_version: str | None = None
    model_params: dict = Field(default_factory=dict, sa_column=_json())
    evidence_ids: list = Field(default_factory=list, sa_column=_json())
    created_at: datetime = _ts_default()


class ReviewDecision(SQLModel, table=True):
    __tablename__ = "review_decisions"
    __table_args__ = (Index("ix_review_decisions_alert_created", "alert_id", "created_at"),)

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id")
    alert_id: str = Field(foreign_key="security_alerts.id")
    assessment_id: str | None = Field(default=None, foreign_key="assessments.id")
    decision: str
    reviewer_note: str | None = None
    # The authenticated user who made the decision.
    reviewer_id: str | None = Field(default=None, foreign_key="users.id")
    created_at: datetime = _ts_default()


class AuditEvent(SQLModel, table=True):
    """Append-only through the application. Nothing in the app updates or deletes these rows."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_alert_created", "alert_id", "created_at"),
        Index("ix_audit_events_org_created", "organization_id", "created_at"),
    )

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id")
    # Null for organization-level events (member added, API key revoked, settings changed).
    alert_id: str | None = Field(default=None, foreign_key="security_alerts.id")
    event_type: str
    actor_type: str
    actor_id: str | None = None
    details: dict = Field(default_factory=dict, sa_column=_json())
    created_at: datetime = _ts_default()


class InvestigationReport(SQLModel, table=True):
    """One generated PDF investigation report: a point-in-time snapshot plus the history of attempts.

    The PDF bytes are kept so a later download is exactly what was generated, even if the alert,
    assessment or decision changes afterwards. A failed attempt keeps its row (status "failed", an error
    code only) and has no file.
    """

    __tablename__ = "investigation_reports"
    __table_args__ = (Index("ix_reports_org_alert_created", "organization_id", "alert_id", "created_at"),)

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id")
    alert_id: str = Field(foreign_key="security_alerts.id")
    report_number: str = Field(sa_column=Column(sa.String, nullable=False, unique=True))  # human-facing, e.g. TIQ-20261030-7F3A9C
    status: str = "generated"  # generated | failed
    classification: str = "Confidential"
    generated_by: str | None = Field(default=None, foreign_key="users.id")
    # What the report was built from, so it can be traced back to the stored records.
    assessment_id: str | None = None
    decision_id: str | None = None
    evidence_count: int = Field(default=0, sa_column_kwargs={"server_default": "0"})
    error_code: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    pdf: bytes | None = Field(default=None, sa_column=Column(sa.LargeBinary, nullable=True))
    created_at: datetime = _ts_default()


# --------------------------------------------------------------------------------------
# Background work and notifications
# --------------------------------------------------------------------------------------


class Job(SQLModel, table=True):
    __tablename__ = "jobs"
    __table_args__ = (
        Index("ix_jobs_org_created", "organization_id", "created_at"),
        UniqueConstraint("organization_id", "idempotency_key", name="uq_job_idempotency"),
    )

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id")
    kind: str  # analyze | enrich | sync | refresh_intel | bulk_ingest
    status: str = "queued"
    progress: int = 0
    message: str | None = None
    subject_id: str | None = None  # e.g. the alert ID
    payload: dict = Field(default_factory=dict, sa_column=_json())
    result: dict = Field(default_factory=dict, sa_column=_json())
    error: str | None = None
    attempts: int = Field(default=0, sa_column_kwargs={"server_default": "0"})
    idempotency_key: str | None = None
    created_by: str | None = Field(default=None, foreign_key="users.id")
    created_at: datetime = _ts_default()
    started_at: datetime | None = None
    finished_at: datetime | None = None


class Notification(SQLModel, table=True):
    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notifications_user_created", "user_id", "created_at"),)

    id: str = Field(default_factory=new_id, primary_key=True)
    organization_id: str = Field(foreign_key="organizations.id")
    user_id: str = Field(foreign_key="users.id")
    kind: str
    title: str
    body: str | None = None
    severity: str | None = None
    link: str | None = None
    read_at: datetime | None = None
    created_at: datetime = _ts_default()
