"""Structured logging, request correlation, security headers, metrics, optional Sentry/OpenTelemetry."""
import asyncio
import contextvars
import json
import logging
import re
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import Settings

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)

# --------------------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------------------

_REDACTIONS = [
    (re.compile(r"tiq_[a-f0-9]{8}_[A-Za-z0-9_\-]{10,}"), "tiq_***REDACTED***"),  # ThreatIQ API keys
    (re.compile(r"(?i)(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{8,}"), r"\1 ***REDACTED***"),
    (re.compile(r"(?i)(authorization|x-api-key|cookie|set-cookie|x-csrf-token)\s*[:=]\s*[^\s,;}]+"), r"\1=***REDACTED***"),
    (re.compile(r"(?i)\"?(password|passwd|secret|api[_-]?key|token|client_secret)\"?\s*[:=]\s*\"?[^\s\",;}]+"), r"\1=***REDACTED***"),
    (re.compile(r"(?i)(tiq_session|tiq_csrf)=[^\s;]+"), r"\1=***REDACTED***"),
]


def redact(text: str) -> str:
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


class JsonFormatter(logging.Formatter):
    _SKIP = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
            "request_id": request_id_var.get(),
        }
        for key, value in record.__dict__.items():
            if key not in self._SKIP and not key.startswith("_"):
                payload[key] = redact(str(value))
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


class RedactingTextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def configure_logging(settings: Settings) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        JsonFormatter() if settings.log_json else RedactingTextFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(settings.log_level.upper())
    # httpx logs full request URLs at INFO; keep provider URLs/params out of logs.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


# --------------------------------------------------------------------------------------
# Metrics (Prometheus)
# --------------------------------------------------------------------------------------

registry = CollectorRegistry()
HTTP_REQUESTS = Counter("threatiq_http_requests_total", "HTTP requests", ["method", "route", "status"], registry=registry)
HTTP_LATENCY = Histogram(
    "threatiq_http_request_duration_seconds", "HTTP request latency", ["method", "route"], registry=registry,
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)
AI_INFERENCE = Counter("threatiq_ai_inference_total", "AI inference calls", ["outcome"], registry=registry)
AI_LATENCY = Histogram(
    "threatiq_ai_inference_duration_seconds", "AI inference latency", registry=registry,
    buckets=(1, 5, 10, 20, 30, 45, 60, 90, 120, 180),
)
PROVIDER_REQUESTS = Counter("threatiq_provider_requests_total", "External provider calls", ["provider", "outcome"], registry=registry)
JOBS = Counter("threatiq_jobs_total", "Background jobs finished", ["kind", "status"], registry=registry)
QUEUE_DEPTH = Gauge("threatiq_job_queue_depth", "Jobs waiting or running", ["status"], registry=registry)
INGESTED = Counter("threatiq_alerts_ingested_total", "Alert events received", ["outcome"], registry=registry)


# --------------------------------------------------------------------------------------
# Middleware
# --------------------------------------------------------------------------------------

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # This is a JSON API; nothing it returns should ever be rendered or framed.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Request ID, size limit, timeout, security headers, access log and metrics."""

    def __init__(self, app, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings
        self.access_log = logging.getLogger("threatiq.access")

    async def dispatch(self, request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if re.fullmatch(r"[A-Za-z0-9\-_.]{8,64}", incoming) else uuid.uuid4().hex
        request.state.request_id = request_id
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        status = 500

        try:
            limit = self.settings.ingest_max_bytes if request.url.path.startswith("/api/v1/ingest") else self.settings.request_max_bytes
            declared = request.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > limit:
                response = JSONResponse(
                    status_code=413,
                    content={"error": {"code": "PAYLOAD_TOO_LARGE", "message": "The request body is too large.", "request_id": request_id}},
                )
            else:
                try:
                    response = await asyncio.wait_for(call_next(request), timeout=self.settings.request_timeout_seconds)
                except asyncio.TimeoutError:
                    response = JSONResponse(
                        status_code=504,
                        content={"error": {"code": "REQUEST_TIMEOUT", "message": "The request took too long.", "request_id": request_id}},
                    )
            status = response.status_code
            response.headers["X-Request-ID"] = request_id
            for name, value in SECURITY_HEADERS.items():
                response.headers.setdefault(name, value)
            if self.settings.is_production:
                response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
            return response
        finally:
            elapsed = time.perf_counter() - started
            route = request.scope.get("route")
            route_path = getattr(route, "path", None) or "unmatched"
            HTTP_REQUESTS.labels(request.method, route_path, str(status)).inc()
            HTTP_LATENCY.labels(request.method, route_path).observe(elapsed)
            if route_path != "/api/v1/health":
                self.access_log.info(
                    "request",
                    extra={"method": request.method, "path": request.url.path, "status": status, "duration_ms": round(elapsed * 1000, 1)},
                )
            request_id_var.reset(token)


def init_error_tracking(app: FastAPI, settings: Settings) -> None:
    """Optional integrations, active only when configured."""
    if settings.sentry_dsn:
        import sentry_sdk

        def _scrub(event, _hint):
            return json.loads(redact(json.dumps(event, default=str)))

        sentry_sdk.init(dsn=settings.sentry_dsn, send_default_pii=False, before_send=_scrub, environment=settings.app_env)
    if settings.otel_exporter_otlp_endpoint:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=Resource.create({"service.name": "threatiq-api"}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint.rstrip("/") + "/v1/traces")))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
