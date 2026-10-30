"""Deterministic indicator extraction (no AI involved) and persistence."""
import ipaddress
import re

from sqlmodel import Session, select

from app.models import AlertIndicator, SecurityAlert

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
URL_RE = re.compile(r"\bhttps?://[^\s<>\"')\]]{3,2000}", re.IGNORECASE)
HASH_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})(?![A-Fa-f0-9])")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b", re.IGNORECASE)

# Bare domains are only trusted with a well-known TLD; this avoids reading file names such as
# "invoice_4471.xlsm" as domains. Domains inside URLs are always extracted.
COMMON_TLDS = {
    "com", "net", "org", "io", "co", "info", "biz", "xyz", "top", "ru", "cn", "de", "uk", "fr", "nl", "br",
    "in", "jp", "kr", "us", "ca", "au", "eu", "su", "tk", "cc", "ws", "me", "ly", "to", "gg", "site", "online",
    "club", "shop", "app", "dev", "cloud", "link", "live", "icu", "work", "pw", "ga", "ml", "cf", "gq", "pro",
}

MAX_INDICATORS = 100


def _hash_type(value: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]


def extract(text: str, affected_entity: str | None = None) -> list[tuple[str, str]]:
    """Return unique (type, normalised_value) pairs found in `text`."""
    found: dict[tuple[str, str], None] = {}

    for m in CVE_RE.findall(text):
        found[("cve", m.upper())] = None
    for m in IPV4_RE.findall(text):
        try:
            found[("ip", str(ipaddress.IPv4Address(m)))] = None
        except ValueError:
            continue
    urls = URL_RE.findall(text)
    for url in urls:
        cleaned = url.rstrip(".,;:")
        found[("url", cleaned.lower())] = None
        host = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE).split("/")[0].split(":")[0].split("@")[-1].lower()
        if host and not IPV4_RE.fullmatch(host):
            found[("domain", host)] = None
    text_without_urls = URL_RE.sub(" ", text)
    for match in DOMAIN_RE.finditer(text_without_urls):
        if match.group(1).lower() in COMMON_TLDS:
            found[("domain", match.group(0).lower())] = None
    for m in HASH_RE.findall(text):
        found[(_hash_type(m), m.lower())] = None
    if affected_entity and affected_entity.strip():
        found[("entity", affected_entity.strip().lower()[:256])] = None
    return list(found)[:MAX_INDICATORS]


def store(session: Session, alert: SecurityAlert, extra: list[tuple[str, str]] | None = None) -> int:
    """Persist indicators for an alert (idempotent). Returns how many were newly added."""
    wanted = dict.fromkeys(extract(f"{alert.title}\n{alert.description}", alert.affected_entity))
    for kind, value in extra or []:
        wanted[(kind, value.strip().lower() if kind not in ("cve",) else value.strip().upper())] = None
    have = {
        (i.type, i.value)
        for i in session.exec(select(AlertIndicator).where(AlertIndicator.alert_id == alert.id)).all()
    }
    added = 0
    for kind, value in list(wanted)[:MAX_INDICATORS]:
        if (kind, value) not in have:
            session.add(AlertIndicator(organization_id=alert.organization_id, alert_id=alert.id, type=kind, value=value))
            added += 1
    return added


def for_alert(session: Session, alert: SecurityAlert) -> list[AlertIndicator]:
    """Indicators for an alert, computing and saving them the first time they are needed."""
    rows = list(session.exec(select(AlertIndicator).where(AlertIndicator.alert_id == alert.id)).all())
    if not rows:
        if store(session, alert):
            session.commit()
            rows = list(session.exec(select(AlertIndicator).where(AlertIndicator.alert_id == alert.id)).all())
    return rows
