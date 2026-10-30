from functools import lru_cache

from pydantic import field_validator, model_validator
from sqlalchemy.engine import make_url
from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_SECRET = "dev-insecure-secret-change-me-dev-insecure-secret"


class Settings(BaseSettings):
    # Later files override earlier ones, so .env.local holds personal secrets.
    model_config = SettingsConfigDict(env_file=(".env", ".env.local"), extra="ignore", env_ignore_empty=True)

    # --- Core ---------------------------------------------------------------------------
    app_env: str = "development"  # development | production
    database_url: str = "sqlite:///./threatiq.db"
    # Used to derive the key that encrypts stored integration credentials. Required in production.
    secret_key: str = _INSECURE_SECRET
    frontend_origin: str = "http://localhost:5173"
    # Extra comma-separated browser origins allowed by CORS (explicit; never "*").
    cors_allowed_origins: str = ""
    log_level: str = "INFO"
    log_json: bool = True
    default_locale: str = "en"
    default_timezone: str = "UTC"

    # --- Authentication -----------------------------------------------------------------
    registration_enabled: bool = True
    session_cookie_name: str = "tiq_session"
    csrf_cookie_name: str = "tiq_csrf"
    session_ttl_hours: int = 12
    cookie_samesite: str = "lax"
    login_max_failures: int = 5
    login_lockout_minutes: int = 15
    password_min_length: int = 10

    # --- Microsoft Entra ID single sign-on (optional; see docs/sso-entra.md) --------------
    # Authorization-code flow with PKCE, run by the backend as a confidential client.
    entra_client_id: str = ""
    entra_client_secret: str = ""
    # Directory (tenant) GUID of a single-tenant app registration. Leave empty only with ENTRA_MULTI_TENANT=true.
    entra_tenant_id: str = ""
    entra_multi_tenant: bool = False
    # Must match a redirect URI registered for the app, e.g. https://app.example.com/api/v1/auth/sso/entra/callback
    entra_redirect_uri: str = ""
    entra_authority_host: str = "https://login.microsoftonline.com"  # sovereign clouds use another host
    # Role for a first-time SSO user whose token carries no ThreatIQ app role. Never "owner".
    entra_default_role: str = "viewer"
    # Create ThreatIQ users on first sign-in. If false, SSO only works for identities created by other means.
    entra_auto_provision: bool = True

    # --- Limits and timeouts ------------------------------------------------------------
    request_timeout_seconds: float = 60.0
    request_max_bytes: int = 1_000_000
    ingest_max_bytes: int = 5_000_000
    rate_limit_login_per_minute: int = 10
    rate_limit_api_per_minute: int = 600
    rate_limit_ingest_per_minute: int = 300
    rate_limit_ai_per_hour: int = 60
    # Automatic triage may use at most this many model analyses per organization per hour, so analysts
    # keep headroom under rate_limit_ai_per_hour. Alerts over the cap stay unanalysed and can be run by hand.
    auto_triage_max_per_hour: int = 30

    # --- Redis / jobs -------------------------------------------------------------------
    # Redis holds transient cache, rate-limit counters and pub/sub only; never the source of truth.
    redis_url: str = ""
    celery_broker_url: str = ""  # defaults to redis_url when set
    job_workers: int = 2
    job_max_attempts: int = 3
    ai_concurrency: int = 2

    # --- Artifact storage (S3) ----------------------------------------------------------
    s3_bucket: str = ""
    s3_region: str = ""
    s3_endpoint_url: str = ""
    s3_prefix: str = "artifacts/"
    artifact_inline_max_bytes: int = 65_536

    # --- AI (Nebius Token Factory) ------------------------------------------------------
    nebius_api_key: str = ""
    nebius_base_url: str = ""
    nebius_model: str = ""
    # Reasoning model: calls take 20-90s and reasoning tokens count toward the output budget.
    nebius_timeout_seconds: float = 120.0
    nebius_max_tokens: int = 12000

    # --- Threat intelligence ------------------------------------------------------------
    intel_timeout_seconds: float = 20.0
    kev_ttl_hours: int = 24
    nvd_ttl_hours: int = 24
    nvd_api_key: str = ""  # optional; raises NVD rate limits
    virustotal_api_key: str = ""  # optional; VirusTotal is used only when this is set AND the org allows it
    enable_historical_retrieval: bool = True
    # --- Retrieval-augmented analysis (RAG) ---------------------------------------------
    # Embeddings come from NVIDIA's hosted API. Alert text is sent there only for organizations that have
    # allow_external_enrichment on. Without a key, or when the call fails, retrieval falls back to keyword + exact.
    rag_enabled: bool = True
    nvidia_api_key: str = ""
    nvidia_base_url: str = "https://integrate.api.nvidia.com/v1"
    embedding_model: str = "nvidia/nemotron-3.5-embed-1b"
    # The model returns 2048; vectors are truncated to this and re-normalised (Matryoshka). Must match the
    # pgvector column created by migration 0006 (1024).
    embedding_dimensions: int = 1024
    embedding_timeout_seconds: float = 20.0
    rag_top_k: int = 5
    rag_max_age_days: int = 365  # older cases are dropped unless they share a strong indicator
    rag_min_similarity: float = 0.5  # cosine floor for semantic-only matches; calibrate with eval/rag_eval.py
    rag_candidate_limit: int = 2000  # most recent embeddings scanned by the SQLite brute-force fallback

    # --- Demo data ----------------------------------------------------------------------
    # Lets an organization admin load clearly labelled synthetic alerts. Keep false in production.
    allow_demo_data: bool = False

    # In-process provider polling. Disable if you run `python -m app.scheduler` separately.
    scheduler_enabled: bool = True

    # --- Observability ------------------------------------------------------------------
    sentry_dsn: str = ""
    otel_exporter_otlp_endpoint: str = ""
    metrics_token: str = ""  # if set, /metrics requires "Authorization: Bearer <token>"

    # SIEM endpoints are often on private networks. Loopback/link-local/metadata addresses are always blocked.
    allow_private_integration_endpoints: bool | None = None

    @property
    def allow_private_endpoints(self) -> bool:
        if self.allow_private_integration_endpoints is not None:
            return self.allow_private_integration_endpoints
        return not self.is_production

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @field_validator("database_url")
    @classmethod
    def _normalize_database_url(cls, value: str) -> str:
        """Accept the connection strings hosting dashboards hand out.

        Supabase and Prisma-style URLs end in ?pgbouncer=true, which libpq rejects as an unknown option.
        It only means "behind a transaction pooler", which database_connect_args handles.
        """
        if not value.startswith("postgres"):
            return value
        url = make_url(value)
        if "pgbouncer" in url.query:
            url = url.set(query={k: v for k, v in url.query.items() if k != "pgbouncer"})
        return url.render_as_string(hide_password=False)

    @property
    def database_connect_args(self) -> dict:
        if self.database_url.startswith("sqlite"):
            return {"check_same_thread": False}
        url = make_url(self.database_url)
        # Transaction poolers (Supabase port 6543, PgBouncer) cannot keep server-side prepared statements.
        if url.port == 6543 or (url.host or "").endswith(".pooler.supabase.com") and url.port != 5432:
            return {"prepare_threshold": None}
        return {}

    @property
    def entra_enabled(self) -> bool:
        return bool(self.entra_client_id and self.entra_client_secret and self.entra_redirect_uri and (self.entra_tenant_id or self.entra_multi_tenant))

    @property
    def entra_authority(self) -> str:
        host = self.entra_authority_host.rstrip("/")
        return f"{host}/organizations" if self.entra_multi_tenant else f"{host}/{self.entra_tenant_id}"

    @property
    def cookie_secure(self) -> bool:
        return self.is_production

    @property
    def effective_broker_url(self) -> str:
        return self.celery_broker_url or self.redis_url

    @property
    def cors_origins(self) -> list[str]:
        extra = [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]
        origins = [self.frontend_origin, *extra]
        if "*" in origins:
            raise ValueError("CORS origins must be explicit; '*' is not allowed.")
        return list(dict.fromkeys(origins))

    @model_validator(mode="after")
    def _validate_production(self) -> "Settings":
        if self.app_env not in ("development", "production"):
            raise ValueError("APP_ENV must be 'development' or 'production'.")
        configured = [bool(self.entra_client_id), bool(self.entra_client_secret), bool(self.entra_redirect_uri), bool(self.entra_tenant_id or self.entra_multi_tenant)]
        if any(configured) and not all(configured):
            raise ValueError(
                "Incomplete Entra ID configuration: set ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET, ENTRA_REDIRECT_URI and "
                "ENTRA_TENANT_ID (or ENTRA_MULTI_TENANT=true), or clear them all."
            )
        if self.entra_enabled:
            if self.entra_default_role not in ("viewer", "analyst", "admin"):
                raise ValueError("ENTRA_DEFAULT_ROLE must be viewer, analyst or admin.")
            if self.entra_multi_tenant and self.entra_tenant_id:
                raise ValueError("Set either ENTRA_TENANT_ID or ENTRA_MULTI_TENANT=true, not both.")
            if self.is_production and not self.entra_redirect_uri.startswith("https://"):
                raise ValueError("ENTRA_REDIRECT_URI must use https in production.")
        if self.is_production:
            problems = []
            if self.secret_key == _INSECURE_SECRET or len(self.secret_key) < 32:
                problems.append("SECRET_KEY must be set to a random value of at least 32 characters")
            if self.database_url.startswith("sqlite"):
                problems.append("DATABASE_URL must point to PostgreSQL (SQLite is for local development only)")
            if self.allow_demo_data:
                problems.append("ALLOW_DEMO_DATA must be false")
            if problems:
                raise ValueError("Invalid production configuration: " + "; ".join(problems) + ".")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
