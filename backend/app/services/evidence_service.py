"""Evidence gathering with provenance.

Every piece of context an assessment may cite is stored as an `evidence_items` row with its source
type, stable source ID, URL, retrieval time, expiry and a content hash. "found", "not_found" and
"error" are distinct recorded outcomes: a provider failure is never presented as "no result".
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlmodel import Session, select

from app import storage
from app.ai.embedding_client import EmbeddingClient
from app.config import get_settings
from app.intel import providers
from app.models import EvidenceItem, Organization, SecurityAlert, utcnow
from app.schemas import RelatedIncident
from app.services import indicators, retrieval_service
from app.services.retrieval_service import RetrievalResult

logger = logging.getLogger(__name__)

Progress = Callable[[int, str], None]


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_stale(item: EvidenceItem) -> bool:
    return item.expires_at is not None and _aware(item.expires_at) <= utcnow()


def _upsert(
    session: Session, alert: SecurityAlert, source_type: str, source_id: str, title: str, content: dict,
    status: str = "found", url: str | None = None, ttl: timedelta | None = None, retrieved_at: datetime | None = None,
) -> EvidenceItem:
    digest = storage.sha256_json({"status": status, "content": content})
    storage_uri = storage.put_if_large(alert.organization_id, source_type, content)
    stored_content = {"_stored_externally": True} if storage_uri else content
    now = retrieved_at or utcnow()
    item = session.exec(
        select(EvidenceItem).where(
            EvidenceItem.alert_id == alert.id, EvidenceItem.source_type == source_type, EvidenceItem.source_id == source_id
        )
    ).first()
    if item is None:
        item = EvidenceItem(organization_id=alert.organization_id, alert_id=alert.id, source_type=source_type, source_id=source_id,
                            title=title, content_hash=digest)
    item.title, item.url, item.provider_status = title, url, status
    item.content, item.content_hash, item.storage_uri = stored_content, digest, storage_uri
    item.retrieved_at = now
    item.expires_at = (now + ttl) if ttl else None
    session.add(item)
    session.flush()
    return item


# ------------------------------------------------------------------------------ internal evidence
def alert_fact_item(session: Session, alert: SecurityAlert) -> EvidenceItem:
    """The original alert as an evidence record, so assessments cite a stored row."""
    return _upsert(
        session, alert, "alert", alert.id, f"Original alert {alert.id}",
        {
            "title": alert.title, "description": alert.description[:8000], "severity": alert.severity, "source": alert.source,
            "affected_entity": alert.affected_entity, "first_seen_at": str(alert.first_seen_at or alert.created_at),
            "occurrence_count": alert.occurrence_count,
        },
        retrieved_at=utcnow(),
    )


def historical_items(
    session: Session, alert: SecurityAlert, embedding_client: EmbeddingClient | None = None
) -> tuple[list[EvidenceItem], RetrievalResult | None]:
    if not get_settings().enable_historical_retrieval:
        return [], None
    items = []
    result = retrieval_service.retrieve(session, alert, embedding_client)
    related: list[RelatedIncident] = result.items
    for r in related:
        content = {"description": r.description, "recorded_outcome": r.outcome, "details": r.details, "matched_on": r.matched_terms,
                   "retrieved_by": r.methods, "reliability": r.reliability}
        if r.occurred_at:
            content["case_created_at"] = r.occurred_at.isoformat()
        if r.decided_at:
            content["analyst_decided_at"] = r.decided_at.isoformat()
        if r.analyst_note:
            content["analyst_note"] = r.analyst_note
        items.append(
            _upsert(session, alert, "historical_alert" if r.kind == "historical_alert" else "demo_incident", r.id,
                    f"Historical case {r.id}", content)
        )
    return items, result


# ------------------------------------------------------------------------------ external intelligence
def providers_status(session: Session, organization: Organization) -> list[dict]:
    settings = get_settings()
    kev = providers.kev_info()
    external_ok = organization.allow_external_enrichment
    return [
        {"provider": "cisa_kev", "configured": True, "available": True,
         "detail": "Public catalog downloaded in full; no alert data is sent." + ("" if kev["fetched_at"] else " Not downloaded yet."),
         "last_refreshed_at": kev["fetched_at"]},
        {"provider": "nvd", "configured": True, "available": external_ok,
         "detail": ("Enabled. CVE IDs (only) are sent to NIST NVD." if external_ok else
                    "Disabled for this organization. An admin can enable external enrichment in organization settings.")
                   + (" API key configured." if settings.nvd_api_key else " No API key (lower rate limit)."),
         "last_refreshed_at": None},
        {"provider": "virustotal", "configured": bool(settings.virustotal_api_key), "available": bool(settings.virustotal_api_key) and external_ok,
         "detail": ("Not configured: set VIRUSTOTAL_API_KEY." if not settings.virustotal_api_key else
                    ("Enabled. Indicator values (only) are sent to VirusTotal." if external_ok else "Disabled for this organization.")),
         "last_refreshed_at": None},
    ]


def enrich(session: Session, alert: SecurityAlert, force: bool = False, progress: Progress | None = None) -> list[EvidenceItem]:
    """Look up the alert's indicators with the providers this organization allows.

    Raises RetryableError (so the job retries with backoff) on rate limits/outages of NVD/VirusTotal.
    """
    settings = get_settings()
    org = session.get(Organization, alert.organization_id)
    report = progress or (lambda _p, _m: None)
    inds = indicators.for_alert(session, alert)
    cves = sorted({i.value for i in inds if i.type == "cve"})
    vt_targets = sorted({(i.type, i.value) for i in inds if providers.vt_supported(i.type)})[:10]
    items: list[EvidenceItem] = []

    existing = {
        (e.source_type, e.source_id): e
        for e in session.exec(select(EvidenceItem).where(EvidenceItem.alert_id == alert.id)).all()
    }

    def fresh(source_type: str, source_id: str) -> EvidenceItem | None:
        e = existing.get((source_type, source_id))
        return e if (e and not force and not is_stale(e) and e.provider_status != "error") else None

    total = max(1, len(cves) * 2 + (len(vt_targets) if (org.allow_external_enrichment and settings.virustotal_api_key) else 0))
    done = 0

    def store(result: providers.ProviderResult) -> None:
        items.append(
            _upsert(session, alert, result.source_type, result.source_id, result.title, result.content,
                    status=result.status, url=result.url, ttl=result.ttl, retrieved_at=result.retrieved_at)
        )
        session.commit()

    for cve in cves:
        report(10 + int(60 * done / total), f"Checking {cve} against CISA KEV")
        cached = fresh("cisa_kev", cve)
        if cached:
            items.append(cached)
        else:
            store(providers.lookup_kev(cve))
        done += 1

        if org.allow_external_enrichment:
            report(10 + int(60 * done / total), f"Looking up {cve} in NVD")
            cached = fresh("nvd", cve)
            if cached:
                items.append(cached)
            else:
                store(providers.lookup_nvd(cve))  # may raise RetryableError
        done += 1

    if org.allow_external_enrichment and settings.virustotal_api_key:
        for kind, value in vt_targets:
            report(10 + int(60 * done / total), f"Checking {kind} reputation")
            cached = fresh("virustotal", value)
            if cached:
                items.append(cached)
            else:
                store(providers.lookup_virustotal(kind, value))
            done += 1
    return items


def list_for_alert(session: Session, organization_id: str, alert_id: str) -> list[EvidenceItem]:
    return list(
        session.exec(
            select(EvidenceItem).where(EvidenceItem.organization_id == organization_id, EvidenceItem.alert_id == alert_id)
            .order_by(EvidenceItem.source_type, EvidenceItem.source_id)
        ).all()
    )


# ------------------------------------------------------------------------------ evidence package for the model
def build_evidence_package(
    session: Session, alert: SecurityAlert, embedding_client: EmbeddingClient | None = None
) -> tuple[dict, set[tuple[str, str]], list[EvidenceItem]]:
    """Assemble the bounded evidence sent to the model from stored evidence rows.

    Returns (package, valid_refs, items). `valid_refs` lists every (source_type, source_id) the model
    may cite; anything else it cites is rejected.
    """
    historical, retrieval = historical_items(session, alert, embedding_client)
    items = [alert_fact_item(session, alert)] + historical
    items += [e for e in list_for_alert(session, alert.organization_id, alert.id) if e.source_type in ("cisa_kev", "nvd", "virustotal")]
    session.commit()

    package = {
        "alert": items[0].content | {"id": alert.id, "created_at": alert.created_at.isoformat()},
        "historical_cases": [
            {"source_type": e.source_type, "id": e.source_id, **e.content} for e in items if e.source_type in ("historical_alert", "demo_incident")
        ],
        "threat_intelligence": [
            {
                "source_type": e.source_type, "id": e.source_id, "lookup_result": e.provider_status,
                "retrieved_at": _aware(e.retrieved_at).isoformat() if e.retrieved_at else None,
                **({"data": e.content} if e.provider_status == "found" else {}),
            }
            for e in items if e.source_type in ("cisa_kev", "nvd", "virustotal")
        ],
    }
    if retrieval is not None:
        package["retrieval"] = {"mode": retrieval.mode, "limitations": retrieval.notes, "candidates": retrieval.counts}
    # Provider errors are not evidence about the alert; they are reported as a limitation instead.
    package["unavailable_sources"] = sorted(
        {e.source_type for e in items if e.provider_status == "error"}
    )
    valid_refs = {(e.source_type, e.source_id) for e in items if e.provider_status in ("found", "not_found")}
    return package, valid_refs, items
