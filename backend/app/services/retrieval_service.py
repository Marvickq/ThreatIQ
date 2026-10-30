"""Hybrid retrieval of earlier cases for an alert.

Stages: exact indicator match (always, highest priority) + keyword search + semantic (embedding) search, fused
with reciprocal rank fusion, then filtered and re-weighted for security use (same organization only, same
demo/real scope, staleness, analyst-decided cases preferred).

Every query is scoped by organization_id. Retrieved text is untrusted: it is data for the model, never
instructions (see ai/prompts.py). Semantic search needs an embedding key and an organization that allows external
enrichment; without them, or when the embedding call fails, the result is keyword + exact and says so.
"""
import logging
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import text
from sqlmodel import Session, select

from app.ai.embedding_client import EmbeddingClient, EmbeddingError
from app.config import get_settings
from app.models import (
    AlertEmbedding,
    AlertIndicator,
    ReviewDecision,
    SecurityAlert,
    utcnow,
)
from app.schemas import RelatedIncident
from app.services import embedding_service, indicators
from app.services.seed_service import load_demo_incidents

logger = logging.getLogger(__name__)

MIN_DEMO_MATCHED_TERMS = 2
# Entities alone (a host or account name) are weak evidence; require at least this many shared
# indicators of any kind, or one strong non-entity indicator.
STRONG_TYPES = {"cve", "ip", "domain", "url", "md5", "sha1", "sha256"}

RRF_K = 60
MIN_KEYWORD_OVERLAP = 3  # distinct shared content words
MIN_KEYWORD_RATIO = 0.25  # ... and at least this share of the alert's content words
KEYWORD_SCAN_LIMIT = 500  # SQLite fallback: most recent alerts scanned
PER_LIST_LIMIT = 25
RECENCY_HALF_LIFE_DAYS = 180.0
RECENCY_FLOOR = 0.5
DECIDED_BOOST = 1.2
NOTE_CHARS = 300

STOPWORDS = frozenset(
    ["the", "and", "for", "with", "from", "that", "this", "was", "were", "has", "have", "had", "are", "not", "but", "all", "any", "can", "its", "into", "over", "under", "out", "off", "via", "per", "than", "then", "them", "they", "their", "there", "here", "been", "being", "will", "would", "could", "should", "about", "after", "before", "again", "alert", "alerts", "detected", "detection", "event", "events", "user", "users", "host", "hosts", "system", "log", "logs", "source"]
)


@dataclass
class Candidate:
    alert_id: str
    exact: list[tuple[str, str]] = field(default_factory=list)
    keyword_terms: list[str] = field(default_factory=list)
    keyword_score: float = 0.0
    similarity: float | None = None


@dataclass
class RetrievalResult:
    items: list[RelatedIncident]
    mode: str  # "hybrid" | "keyword_exact"
    notes: list[str] = field(default_factory=list)  # limitations the model and analyst should know about
    counts: dict[str, int] = field(default_factory=dict)  # per-stage candidates, for audit and evaluation


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _words(value: str) -> list[str]:
    out = []
    for w in re.findall(r"[a-z][a-z0-9_\-]{2,}", value.lower()):
        if w not in STOPWORDS and w not in out:
            out.append(w)
    return out


# ------------------------------------------------------------------------------ stage 1: exact indicators
def _exact_matches(session: Session, alert: SecurityAlert) -> dict[str, list[tuple[str, str]]]:
    mine = indicators.for_alert(session, alert)
    if not mine:
        return {}
    pairs = {(i.type, i.value) for i in mine}
    rows = session.exec(
        select(AlertIndicator).where(
            AlertIndicator.organization_id == alert.organization_id,
            AlertIndicator.alert_id != alert.id,
            AlertIndicator.value.in_({v for _, v in pairs}),
        )
    ).all()
    shared: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for r in rows:
        if (r.type, r.value) in pairs:
            shared[r.alert_id].append((r.type, r.value))
    return {
        aid: terms for aid, terms in shared.items()
        if len(terms) >= 2 or any(t in STRONG_TYPES for t, _ in terms)
    }


# ------------------------------------------------------------------------------ stage 2: keyword search
def _keyword_matches(session: Session, alert: SecurityAlert) -> dict[str, tuple[list[str], float]]:
    """alert_id -> (shared content words, score). PostgreSQL full-text ranks; SQLite scans recent alerts."""
    mine = _words(f"{alert.title} {alert.description}")[:40]
    if len(mine) < MIN_KEYWORD_OVERLAP:
        return {}
    org, demo = alert.organization_id, alert.is_demo

    if embedding_service.has_fulltext(session):
        # Tokens are reduced to [a-z0-9] and joined with OR; the query is passed as a bound parameter.
        query = " | ".join(re.sub(r"[^a-z0-9]+", "&", w).strip("&") for w in mine)
        rows = session.execute(
            text(
                "SELECT id, title, description, ts_rank_cd(to_tsvector('english', coalesce(title,'') || ' ' || coalesce(description,'')), "
                "to_tsquery('english', :q)) AS rank FROM security_alerts "
                "WHERE organization_id = :org AND id <> :id AND is_demo = :demo "
                "AND to_tsvector('english', coalesce(title,'') || ' ' || coalesce(description,'')) @@ to_tsquery('english', :q) "
                "ORDER BY rank DESC LIMIT :n"
            ),
            {"q": query, "org": org, "id": alert.id, "demo": demo, "n": PER_LIST_LIMIT * 2},
        ).all()
        scored = [(r.id, _words(f"{r.title} {r.description}"), float(r.rank)) for r in rows]
    else:
        rows = session.exec(
            select(SecurityAlert)
            .where(SecurityAlert.organization_id == org, SecurityAlert.id != alert.id, SecurityAlert.is_demo == demo)
            .order_by(SecurityAlert.created_at.desc()).limit(KEYWORD_SCAN_LIMIT)
        ).all()
        docs = {r.id: set(_words(f"{r.title} {r.description}")) for r in rows}
        df: dict[str, int] = defaultdict(int)
        for words in docs.values():
            for w in words:
                df[w] += 1
        n = max(len(docs), 1)
        scored = [
            (aid, list(words), sum(math.log(1 + n / (1 + df[w])) for w in mine if w in words))
            for aid, words in docs.items()
        ]

    out: dict[str, tuple[list[str], float]] = {}
    for aid, words, score in scored:
        shared = [w for w in mine if w in set(words)]
        if len(shared) >= MIN_KEYWORD_OVERLAP and len(shared) / len(mine) >= MIN_KEYWORD_RATIO and score > 0:
            out[aid] = (shared[:8], score)
    return dict(sorted(out.items(), key=lambda kv: -kv[1][1])[:PER_LIST_LIMIT])


# ------------------------------------------------------------------------------ stage 3: semantic search
def _cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))  # both unit length


def _semantic_matches(session: Session, alert: SecurityAlert, qvec: list[float], model: str) -> dict[str, float]:
    settings = get_settings()
    org, demo = alert.organization_id, alert.is_demo
    if embedding_service.has_pgvector(session):
        literal = "[" + ",".join(f"{x:.7g}" for x in qvec) + "]"
        rows = session.execute(
            text(
                "SELECT e.alert_id AS aid, 1 - (e.embedding_vec <=> CAST(:q AS vector)) AS sim "
                "FROM alert_embeddings e JOIN security_alerts a ON a.id = e.alert_id "
                "WHERE e.organization_id = :org AND a.organization_id = :org AND e.model = :model "
                "AND a.id <> :id AND a.is_demo = :demo AND e.embedding_vec IS NOT NULL "
                "ORDER BY e.embedding_vec <=> CAST(:q AS vector) LIMIT :n"
            ),
            {"q": literal, "org": org, "model": model, "id": alert.id, "demo": demo, "n": PER_LIST_LIMIT},
        ).all()
        sims = {r.aid: float(r.sim) for r in rows}
    else:
        rows = session.exec(
            select(AlertEmbedding, SecurityAlert.id)
            .join(SecurityAlert, SecurityAlert.id == AlertEmbedding.alert_id)
            .where(
                AlertEmbedding.organization_id == org, SecurityAlert.organization_id == org, AlertEmbedding.model == model,
                SecurityAlert.id != alert.id, SecurityAlert.is_demo == demo, AlertEmbedding.dimensions == len(qvec),
            )
            .order_by(SecurityAlert.created_at.desc()).limit(settings.rag_candidate_limit)
        ).all()
        sims = {aid: _cosine(qvec, e.embedding) for e, aid in rows if len(e.embedding) == len(qvec)}
    kept = {a: s for a, s in sims.items() if s >= settings.rag_min_similarity}
    return dict(sorted(kept.items(), key=lambda kv: -kv[1])[:PER_LIST_LIMIT])


# ------------------------------------------------------------------------------ fusion, filtering, ranking
def _latest_decisions(session: Session, organization_id: str, alert_ids: list[str]) -> dict[str, ReviewDecision]:
    if not alert_ids:
        return {}
    latest: dict[str, ReviewDecision] = {}
    for d in session.exec(
        select(ReviewDecision)
        .where(ReviewDecision.organization_id == organization_id, ReviewDecision.alert_id.in_(alert_ids))
        .order_by(ReviewDecision.created_at)
    ).all():
        latest[d.alert_id] = d
    return latest


def _rank_map(ordered_ids: list[str]) -> dict[str, int]:
    return {aid: i + 1 for i, aid in enumerate(ordered_ids)}


def _build(
    session: Session, alert: SecurityAlert, cands: dict[str, Candidate], notes: list[str],
    demo: dict[str, tuple[dict, list[str]]] | None = None,
) -> list[RelatedIncident]:
    settings = get_settings()
    org = alert.organization_id
    others = {
        a.id: a for a in session.exec(
            select(SecurityAlert).where(
                SecurityAlert.organization_id == org, SecurityAlert.is_demo == alert.is_demo, SecurityAlert.id.in_(list(cands) or [""])
            )
        ).all()
    }
    decisions = _latest_decisions(session, org, list(others))

    exact_rank = _rank_map(sorted((a for a, c in cands.items() if c.exact), key=lambda a: -len(cands[a].exact)))
    kw_rank = _rank_map(sorted((a for a, c in cands.items() if c.keyword_terms), key=lambda a: -cands[a].keyword_score))
    sem_rank = _rank_map(sorted((a for a, c in cands.items() if c.similarity is not None), key=lambda a: -(cands[a].similarity or 0)))

    # Demo incidents are not alert rows, so they have no age or analyst decision; they join the fusion as their own
    # keyword-style rank list (by number of matched keywords). Fusion compares list *positions*, never raw scores of
    # different kinds, so an incident and an alert are ranked consistently.
    demo = demo or {}
    demo_rank = _rank_map(sorted(demo, key=lambda i: (-len(demo[i][1]), i)))

    now, stale = utcnow(), 0
    ranked: list[tuple[tuple, RelatedIncident]] = []
    for aid, cand in cands.items():
        other = others.get(aid)
        if other is None:
            continue
        strong_exact = any(t in STRONG_TYPES for t, _ in cand.exact)
        age_days = max((now - _aware(other.created_at)).total_seconds() / 86400, 0)
        if age_days > settings.rag_max_age_days and not strong_exact:
            stale += 1
            continue
        fused = sum(1 / (RRF_K + r[aid]) for r in (exact_rank, kw_rank, sem_rank) if aid in r) * RRF_K
        decision = decisions.get(aid)
        weight = max(RECENCY_FLOOR, 0.5 ** (age_days / RECENCY_HALF_LIFE_DAYS)) * (DECIDED_BOOST if decision else 1.0)
        methods = [m for m, present in (("exact", bool(cand.exact)), ("keyword", bool(cand.keyword_terms)), ("semantic", cand.similarity is not None)) if present]
        terms = [f"{t}:{v}" for t, v in cand.exact] + [f"keyword:{w}" for w in cand.keyword_terms[:5]]
        if cand.similarity is not None:
            terms.append(f"semantic:{cand.similarity:.2f}")
        note = (decision.reviewer_note or "").strip()[:NOTE_CHARS] if decision else ""
        score = round(fused * weight, 3)
        ranked.append((
            (strong_exact, score, aid),  # exact indicator matches always outrank text-similarity matches
            RelatedIncident(
                id=other.id, kind="historical_alert", description=other.title,
                outcome=decision.decision if decision else "no human decision recorded",
                details=f"{other.severity} severity alert from {other.source}, status {other.status}.",
                matched_terms=terms, score=score, methods=methods, occurred_at=_aware(other.created_at),
                reliability="analyst_decided" if decision else "undecided",
                decided_at=_aware(decision.created_at) if decision else None, analyst_note=note or None,
            ),
        ))
    for iid, (incident, matched) in demo.items():
        score = round(1 / (RRF_K + demo_rank[iid]) * RRF_K, 3)
        ranked.append((
            (False, score, iid),
            RelatedIncident(
                id=iid, kind="demo_incident", description=incident["description"], outcome=incident["outcome"],
                details=incident["details"], matched_terms=matched, score=score, methods=["keyword"], reliability="synthetic",
            ),
        ))
    if stale:
        notes.append(f"{stale} older case(s) beyond {settings.rag_max_age_days} days were excluded.")
    # Strong exact indicator matches first, then fused score; ties break by id ascending so results are deterministic.
    ranked.sort(key=lambda r: r[0][2])
    ranked.sort(key=lambda r: (r[0][0], r[0][1]), reverse=True)
    return [r for _, r in ranked[: settings.rag_top_k]]


def _demo_matches(alert: SecurityAlert) -> dict[str, tuple[dict, list[str]]]:
    """Keyword matching against the synthetic incident file: incident id -> (incident, matched keywords). Demo alerts only."""
    if not alert.is_demo:
        return {}
    haystack = f" {re.sub(r'[^a-z0-9]+', ' ', (alert.title + ' ' + alert.description).lower()).strip()} "
    out = {}
    for incident in load_demo_incidents():
        matched = [kw for kw in incident.get("keywords", []) if f" {re.sub(r'[^a-z0-9]+', ' ', kw.lower()).strip()} " in haystack]
        if len(matched) >= MIN_DEMO_MATCHED_TERMS:
            out[incident["id"]] = (incident, matched)
    return out


def retrieve(session: Session, alert: SecurityAlert, client: EmbeddingClient | None = None) -> RetrievalResult:
    """Hybrid retrieval. Pass an EmbeddingClient to include semantic search (this may call the embedding API).

    Never raises for retrieval trouble: each stage that fails is skipped and reported in `notes`.
    """
    settings = get_settings()
    notes: list[str] = []
    cands: dict[str, Candidate] = {}
    counts = {"exact": 0, "keyword": 0, "semantic": 0}

    try:
        for aid, terms in _exact_matches(session, alert).items():
            cands.setdefault(aid, Candidate(aid)).exact = terms
        counts["exact"] = len(cands)
    except Exception:
        logger.exception("Exact retrieval failed")
        session.rollback()
        notes.append("Exact indicator matching was unavailable.")

    if settings.rag_enabled:
        try:
            kw = _keyword_matches(session, alert)
            for aid, (terms, score) in kw.items():
                c = cands.setdefault(aid, Candidate(aid))
                c.keyword_terms, c.keyword_score = terms, score
            counts["keyword"] = len(kw)
        except Exception:
            logger.exception("Keyword retrieval failed")
            session.rollback()
            notes.append("Keyword search was unavailable.")

    mode = "keyword_exact"
    if settings.rag_enabled and client is not None:
        ok, why = embedding_service.allowed(session, alert.organization_id)
        if not ok:
            notes.append(f"Semantic search was not used: {why}")
        else:
            try:
                embedding_service.index_alerts(session, [alert], client)  # the alert becomes searchable for later ones
                qvec = embedding_service.query_vector(session, alert, client)
                sem = _semantic_matches(session, alert, qvec, client.model)
                for aid, sim in sem.items():
                    cands.setdefault(aid, Candidate(aid)).similarity = sim
                counts["semantic"] = len(sem)
                mode = "hybrid"
                if not sem:
                    notes.append("Semantic search ran but found no sufficiently similar earlier case (earlier cases may not be indexed yet).")
            except EmbeddingError as exc:
                session.rollback()
                notes.append(f"Semantic search was unavailable ({exc.code}); results are keyword + exact only.")
            except Exception:
                logger.exception("Semantic retrieval failed")
                session.rollback()
                notes.append("Semantic search failed; results are keyword + exact only.")

    try:
        items = _build(session, alert, cands, notes, _demo_matches(alert))
    except Exception:
        logger.exception("Ranking failed")
        session.rollback()
        items = []
        notes.append("Retrieval ranking failed; no historical cases are included.")
    return RetrievalResult(items=items, mode=mode, notes=notes, counts=counts)


def find_related_incidents(session: Session, alert: SecurityAlert) -> list[RelatedIncident]:
    """Read-path retrieval (no outbound embedding call): exact + keyword only."""
    return retrieve(session, alert, client=None).items
