"""Request/response schemas for the multi-tenant SaaS surface (auth, org, keys, ingestion, jobs, ...)."""
import re
from datetime import datetime, timezone
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

Role = Literal["viewer", "analyst", "admin", "owner"]
Scope = Literal["alerts:read", "alerts:write", "ingest:write"]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ------------------------------------------------------------------ auth & account
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    display_name: str = Field(min_length=1, max_length=100)
    organization_name: str = Field(min_length=2, max_length=100)

    @field_validator("display_name", "organization_name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be blank")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class SwitchOrganizationRequest(BaseModel):
    organization_id: str


class NotificationPrefs(BaseModel):
    in_app: bool = True
    min_severity: Literal["low", "medium", "high", "critical"] = "high"
    on_assignment: bool = True
    on_job_failure: bool = True


def _valid_timezone(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise ValueError("unknown time zone (use an IANA name such as Europe/London)")
    return value


class UpdateProfileRequest(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    locale: str | None = Field(default=None, max_length=20, pattern=r"^[A-Za-z]{2,3}([-_][A-Za-z0-9]{2,8})*$")
    timezone: str | None = Field(default=None, max_length=64)
    notification_prefs: NotificationPrefs | None = None

    _tz = field_validator("timezone")(_valid_timezone)


class UserOut(ORM):
    id: str
    email: str
    display_name: str
    locale: str | None
    timezone: str | None
    notification_prefs: dict
    created_at: datetime
    last_login_at: datetime | None


class OrganizationOut(ORM):
    id: str
    name: str
    slug: str
    default_locale: str
    default_timezone: str
    retention_days: int
    allow_external_enrichment: bool
    auto_triage_enabled: bool
    created_at: datetime


class MembershipOut(BaseModel):
    organization_id: str
    organization_name: str
    role: Role


class SecurityInfo(BaseModel):
    """The server's real sign-in and session policy, so the UI never hard-codes it."""

    password_min_length: int
    session_ttl_hours: int
    login_max_failures: int
    login_lockout_minutes: int
    sso_user: bool  # this account signs in with Microsoft and has no usable password
    sso_available: bool


class MeResponse(BaseModel):
    user: UserOut
    organization: OrganizationOut
    role: Role
    memberships: list[MembershipOut]
    csrf_token: str
    capabilities: list[str]
    demo_data_allowed: bool
    security: SecurityInfo


class SessionOut(BaseModel):
    id: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip: str | None
    user_agent: str | None
    current: bool


# ------------------------------------------------------------------ organization
class UpdateOrganizationRequest(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    default_locale: str | None = Field(default=None, max_length=20, pattern=r"^[A-Za-z]{2,3}([-_][A-Za-z0-9]{2,8})*$")
    default_timezone: str | None = Field(default=None, max_length=64)
    retention_days: int | None = Field(default=None, ge=0, le=36500)
    allow_external_enrichment: bool | None = None
    auto_triage_enabled: bool | None = None

    _tz = field_validator("default_timezone")(_valid_timezone)


class MemberOut(BaseModel):
    user_id: str
    email: str
    display_name: str
    role: Role
    joined_at: datetime
    last_login_at: datetime | None


class AddMemberRequest(BaseModel):
    email: EmailStr
    role: Role = "analyst"


class UpdateMemberRequest(BaseModel):
    role: Role


# ------------------------------------------------------------------ API keys
class CreateApiKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[Scope] = Field(min_length=1)
    expires_in_days: int | None = Field(default=90, ge=1, le=730)


class ApiKeyOut(ORM):
    id: str
    name: str
    prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    use_count: int


class ApiKeyCreated(ApiKeyOut):
    key: str  # shown exactly once


# ------------------------------------------------------------------ ingestion
_SEVERITY_ALIASES = {
    "info": "low", "informational": "low", "notice": "low", "low": "low",
    "warning": "medium", "warn": "medium", "medium": "medium", "moderate": "medium",
    "high": "high", "error": "high", "major": "high",
    "critical": "critical", "fatal": "critical", "severe": "critical", "emergency": "critical",
}


def normalize_severity(value: str) -> str:
    try:
        return _SEVERITY_ALIASES[value.strip().lower()]
    except KeyError:
        raise ValueError("severity must be one of: low, medium, high, critical (or a common alias)")


class IndicatorIn(BaseModel):
    type: Literal["ip", "domain", "url", "md5", "sha1", "sha256", "cve", "account", "host"]
    value: str = Field(min_length=1, max_length=2048)


class IngestEvent(BaseModel):
    """Generic JSON webhook event. See docs/integrations.md."""

    source: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    external_id: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=20_000)
    severity: str
    event_time: datetime | None = None
    affected_entity: str | None = Field(default=None, max_length=256)
    indicators: list[IndicatorIn] = Field(default_factory=list, max_length=100)
    raw: dict | None = None

    @field_validator("severity")
    @classmethod
    def _severity(cls, v: str) -> str:
        return normalize_severity(v)

    @field_validator("event_time")
    @classmethod
    def _utc(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v.astimezone(timezone.utc)


class IngestBatch(BaseModel):
    events: list[IngestEvent] = Field(min_length=1, max_length=500)


class IngestResult(BaseModel):
    outcome: Literal["created", "duplicate", "updated", "out_of_order"]
    alert_id: str
    occurrence_count: int


class BatchIngestAccepted(BaseModel):
    job_id: str
    accepted: int


# ------------------------------------------------------------------ integrations
class IntegrationCreate(BaseModel):
    kind: Literal["webhook", "wazuh", "elastic"]
    name: str = Field(min_length=1, max_length=100)
    # Non-secret settings, e.g. {"endpoint": "https://...", "index": "wazuh-alerts-*", "min_level": 7}
    config: dict = Field(default_factory=dict)
    # Write-only credentials, stored encrypted and never returned.
    credentials: dict = Field(default_factory=dict)
    enabled: bool = True


class IntegrationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    config: dict | None = None
    credentials: dict | None = None
    enabled: bool | None = None


class IntegrationOut(BaseModel):
    id: str
    kind: str
    name: str
    enabled: bool
    config: dict
    status: str
    has_credentials: bool
    last_sync_at: datetime | None
    last_success_at: datetime | None
    last_error: str | None
    created_at: datetime


# ------------------------------------------------------------------ jobs, evidence, intel
class JobOut(ORM):
    id: str
    kind: str
    status: str
    progress: int
    message: str | None
    subject_id: str | None
    result: dict
    error: str | None
    attempts: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class JobList(BaseModel):
    items: list[JobOut]
    total: int


class EvidenceOut(ORM):
    id: str
    alert_id: str
    source_type: str
    source_id: str
    title: str
    url: str | None
    provider_status: str
    content: dict
    content_hash: str
    confidence: float | None
    retrieved_at: datetime
    expires_at: datetime | None
    stale: bool = False


class EvidenceList(BaseModel):
    items: list[EvidenceOut]


class IndicatorOut(ORM):
    type: str
    value: str


class ProviderStatus(BaseModel):
    provider: str
    configured: bool
    available: bool
    detail: str
    last_refreshed_at: datetime | None = None


# ------------------------------------------------------------------ dashboard, notifications
class AlertRow(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    source: str
    created_at: datetime
    is_demo: bool


class ActivityItem(BaseModel):
    id: str
    event_type: str
    actor_type: str
    alert_id: str | None
    created_at: datetime


DataScope = Literal["real", "demo", "all"]
ReviewState = Literal["unreviewed", "reviewed", "true_positive", "false_positive", "needs_further_review"]


class DashboardFilters(BaseModel):
    """The filters a dashboard response was computed with, echoed back so the UI can show them."""

    data_scope: DataScope
    severity: str | None = None
    status: str | None = None
    assigned_to: str | None = None
    review_state: str | None = None


class DataSourceCounts(BaseModel):
    """Whole-organization counts, ignoring filters, so the UI can say what the other scope holds."""

    real: int
    demo: int


class DashboardSummary(BaseModel):
    generated_at: datetime
    filters: DashboardFilters
    sources: DataSourceCounts
    total: int
    unresolved: int
    high_or_critical: int
    awaiting_review: int
    unreviewed: int  # alerts with no persisted human review decision
    recent_alerts: list[AlertRow]
    activity: list[ActivityItem]


class SeverityCount(BaseModel):
    severity: str
    count: int


class SeverityDistribution(BaseModel):
    generated_at: datetime
    filters: DashboardFilters
    total: int
    items: list[SeverityCount]  # always critical, high, medium, low


class DailyCount(BaseModel):
    date: str  # UTC calendar day, YYYY-MM-DD
    count: int


class DailyAlertCounts(BaseModel):
    generated_at: datetime
    filters: DashboardFilters
    timezone: Literal["UTC"] = "UTC"
    days: int
    total: int
    items: list[DailyCount]  # oldest first, one entry per day including zero days


class QueueItem(BaseModel):
    key: str
    label: str
    count: int
    # Alert-list query parameters that reproduce this queue; null when the active filters contradict the queue.
    query: dict[str, str] | None


class InvestigationQueues(BaseModel):
    generated_at: datetime
    filters: DashboardFilters
    items: list[QueueItem]


class NotificationOut(ORM):
    id: str
    kind: str
    title: str
    body: str | None
    severity: str | None
    link: str | None
    read_at: datetime | None
    created_at: datetime


_SAFE_ID = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


class BulkStatusRequest(BaseModel):
    alert_ids: list[str] = Field(min_length=1, max_length=200)
    status: Literal["new", "investigating", "awaiting_review", "resolved"]

    @field_validator("alert_ids")
    @classmethod
    def _ids(cls, v: list[str]) -> list[str]:
        if any(not _SAFE_ID.match(i) for i in v):
            raise ValueError("alert_ids contains an invalid identifier")
        return list(dict.fromkeys(v))


class BulkStatusResult(BaseModel):
    updated: int
    unchanged: int
    not_found: list[str]


class AssignRequest(BaseModel):
    user_id: str | None = None


# ------------------------------------------------------------------ investigation reports
ReportClassification = Literal["Public", "Internal", "Confidential", "Restricted"]


class GenerateReportRequest(BaseModel):
    classification: ReportClassification = "Confidential"


class ReportOut(BaseModel):
    id: str
    alert_id: str
    report_number: str
    status: Literal["generated", "failed"]
    classification: str
    generated_by: str | None
    generated_by_name: str | None = None
    assessment_id: str | None
    decision_id: str | None
    evidence_count: int
    error_code: str | None
    size_bytes: int | None
    sha256: str | None
    created_at: datetime
