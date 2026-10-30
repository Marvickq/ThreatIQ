"""Normalise alerts to text, embed them, and store the vectors.

Embedding is best-effort: any failure leaves the alert un-indexed and retrieval falls back to keyword + exact.
Alert text leaves the system only for organizations that enabled external enrichment.
"""
import hashlib
import logging
from dataclasses import dataclass

from sqlalchemy import text
from sqlmodel import Session, select

from app.ai.embedding_client import EmbeddingClient, EmbeddingError
from app.config import get_settings
from app.models import AlertEmbedding, AlertIndicator, Organization, SecurityAlert

logger = logging.getLogger(__name__)

MAX_TEXT_CHARS = 6000
_vec_support: dict[str, bool] = {}


def has_pgvector(session: Session) -> bool:
    """True when this database has the pgvector column from migration 0006 (PostgreSQL only)."""
    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return False
    key = bind.engine.url.render_as_string(hide_password=True)
    if key not in _vec_support:
        try:
            _vec_support[key] = session.execute(
                text("SELECT 1 FROM information_schema.columns WHERE table_name = 'alert_embeddings' AND column_name = 'embedding_vec' AND table_schema = current_schema()")
            ).first() is not None
        except Exception:
            return False
    return _vec_support[key]


def has_fulltext(session: Session) -> bool:
    return session.get_bind().dialect.name == "postgresql"


def allowed(session: Session, organization_id: str) -> tuple[bool, str | None]:
    """Whether this organization's alert text may be sent to the embedding provider, and why not."""
    settings = get_settings()
    if not settings.rag_enabled:
        return False, "RAG is disabled (RAG_ENABLED=false)."
    if not settings.nvidia_api_key:
        return False, "Embeddings are not configured (NVIDIA_API_KEY)."
    org = session.get(Organization, organization_id)
    if org is None or not org.allow_external_enrichment:
        return False, "External enrichment is disabled for this organization, so alert text is not sent for embedding."
    return True, None


def alert_text(alert: SecurityAlert, indicators: list[tuple[str, str]]) -> str:
    """The normalised representation that is embedded: stable field order, bounded size, no ids or timestamps."""
    inds = ", ".join(f"{t}:{v}" for t, v in sorted(indicators) if t != "entity")[:600]
    parts = [
        f"Title: {alert.title}",
        f"Source: {alert.source}; severity: {alert.severity}",
        f"Entity: {alert.affected_entity}" if alert.affected_entity else "",
        f"Indicators: {inds}" if inds else "",
        f"Description: {alert.description}",
    ]
    return "\n".join(p for p in parts if p)[:MAX_TEXT_CHARS]


def _hash(model: str, body: str) -> str:
    return hashlib.sha256(f"{model}\n{body}".encode()).hexdigest()


def _indicators(session: Session, alert_id: str) -> list[tuple[str, str]]:
    return [(i.type, i.value) for i in session.exec(select(AlertIndicator).where(AlertIndicator.alert_id == alert_id)).all()]


def _write(session: Session, row: AlertEmbedding, vector: list[float]) -> None:
    session.add(row)
    session.flush()
    if has_pgvector(session):
        literal = "[" + ",".join(f"{x:.7g}" for x in vector) + "]"
        session.execute(text("UPDATE alert_embeddings SET embedding_vec = CAST(:v AS vector) WHERE id = :id"), {"v": literal, "id": row.id})


@dataclass
class IndexResult:
    indexed: int = 0
    unchanged: int = 0
    failed: int = 0
    error: str | None = None


def index_alerts(session: Session, alerts: list[SecurityAlert], client: EmbeddingClient) -> IndexResult:
    """Embed alerts whose text is new or changed. Caller must have checked `allowed()` for the organization."""
    result = IndexResult()
    todo: list[tuple[SecurityAlert, str, str, AlertEmbedding | None]] = []
    for alert in alerts:
        body = alert_text(alert, _indicators(session, alert.id))
        digest = _hash(client.model, body)
        existing = session.exec(
            select(AlertEmbedding).where(AlertEmbedding.alert_id == alert.id, AlertEmbedding.model == client.model)
        ).first()
        if existing and existing.text_hash == digest and existing.dimensions == client.dimensions:
            result.unchanged += 1
        else:
            todo.append((alert, body, digest, existing))
    if not todo:
        return result
    try:
        vectors = client.embed([b for _, b, _, _ in todo], "passage")
    except EmbeddingError as exc:
        result.failed = len(todo)
        result.error = exc.code
        return result
    for (alert, _body, digest, existing), vector in zip(todo, vectors):
        row = existing or AlertEmbedding(organization_id=alert.organization_id, alert_id=alert.id, model=client.model, dimensions=client.dimensions, text_hash=digest)
        row.text_hash, row.dimensions, row.embedding = digest, client.dimensions, vector
        _write(session, row, vector)
        result.indexed += 1
    session.commit()
    return result


def query_vector(session: Session, alert: SecurityAlert, client: EmbeddingClient) -> list[float]:
    """Embedding of the alert as a *query*. Not stored."""
    return client.embed([alert_text(alert, _indicators(session, alert.id))], "query")[0]
