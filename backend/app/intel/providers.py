"""External threat-intelligence providers.

Outbound hosts are fixed constants (no user-supplied URLs), so these calls cannot be steered at
internal addresses. Only indicator identifiers are sent (a CVE ID or a hash/IP/domain/URL for
VirusTotal) - never alert text. Callers decide whether a provider may be used for an organization.
"""
import base64
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx

from app.config import get_settings
from app.jobs import RetryableError
from app.observability import PROVIDER_REQUESTS

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VT_BASE = "https://www.virustotal.com/api/v3"

USER_AGENT = "ThreatIQ/2.0 (+security alert investigation)"


class ProviderError(Exception):
    """The provider could not answer. Recorded as an 'error' result, never as 'not found'."""


@dataclass
class ProviderResult:
    status: str  # found | not_found | error
    source_type: str
    source_id: str
    title: str
    url: str | None = None
    content: dict = field(default_factory=dict)
    ttl: timedelta = timedelta(hours=24)
    retrieved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _client() -> httpx.Client:
    return httpx.Client(timeout=get_settings().intel_timeout_seconds, follow_redirects=False, headers={"User-Agent": USER_AGENT})


# ------------------------------------------------------------------------------ CISA KEV
_kev_lock = threading.Lock()
_kev: dict = {"fetched_at": None, "by_cve": {}, "version": None, "count": 0}


def kev_info() -> dict:
    return {"fetched_at": _kev["fetched_at"], "version": _kev["version"], "count": _kev["count"]}


def refresh_kev(force: bool = False) -> dict:
    """Download the full catalog (nothing about any alert is sent). Falls back to the last good copy."""
    ttl = timedelta(hours=get_settings().kev_ttl_hours)
    with _kev_lock:
        fetched = _kev["fetched_at"]
        if not force and fetched is not None and datetime.now(timezone.utc) - fetched < ttl:
            return kev_info()
        try:
            with _client() as client:
                response = client.get(KEV_URL)
            if response.status_code != 200:
                raise ProviderError(f"CISA KEV returned HTTP {response.status_code}")
            data = response.json()
            _kev.update(
                fetched_at=datetime.now(timezone.utc),
                by_cve={v["cveID"].upper(): v for v in data.get("vulnerabilities", [])},
                version=data.get("catalogVersion"),
                count=len(data.get("vulnerabilities", [])),
            )
            PROVIDER_REQUESTS.labels("cisa_kev", "ok").inc()
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            PROVIDER_REQUESTS.labels("cisa_kev", "error").inc()
            if _kev["fetched_at"] is None:
                raise ProviderError(f"CISA KEV is unavailable ({type(exc).__name__})") from exc
            logger.warning("KEV refresh failed (%s); using the cached catalog", type(exc).__name__)
        except ProviderError:
            PROVIDER_REQUESTS.labels("cisa_kev", "error").inc()
            if _kev["fetched_at"] is None:
                raise
    return kev_info()


def lookup_kev(cve: str) -> ProviderResult:
    cve = cve.upper()
    try:
        refresh_kev()
    except ProviderError as exc:
        return ProviderResult("error", "cisa_kev", cve, f"CISA KEV: {cve}", content={"error": str(exc)})
    entry = _kev["by_cve"].get(cve)
    url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    if entry is None:
        return ProviderResult(
            "not_found", "cisa_kev", cve, f"CISA KEV: {cve}", url,
            {"catalog_version": _kev["version"], "catalog_size": _kev["count"], "catalog_fetched_at": str(_kev["fetched_at"])},
            ttl=timedelta(hours=get_settings().kev_ttl_hours),
        )
    return ProviderResult(
        "found", "cisa_kev", cve, f"CISA KEV: {cve}", url,
        {
            "cve": entry.get("cveID"), "vendor": entry.get("vendorProject"), "product": entry.get("product"),
            "name": entry.get("vulnerabilityName"), "date_added": entry.get("dateAdded"),
            "description": (entry.get("shortDescription") or "")[:1500], "required_action": (entry.get("requiredAction") or "")[:800],
            "due_date": entry.get("dueDate"), "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
            "catalog_version": _kev["version"],
        },
        ttl=timedelta(hours=get_settings().kev_ttl_hours),
    )


# ------------------------------------------------------------------------------ NVD
_nvd_lock = threading.Lock()
_nvd_calls: deque[float] = deque()


def _nvd_wait() -> None:
    """Stay under NVD's published limit: 5 requests / 30s without a key, 50 / 30s with one."""
    limit = 50 if get_settings().nvd_api_key else 5
    with _nvd_lock:
        now = time.monotonic()
        while _nvd_calls and now - _nvd_calls[0] > 30:
            _nvd_calls.popleft()
        if len(_nvd_calls) >= limit:
            time.sleep(max(0.0, 30 - (now - _nvd_calls[0])) + 0.2)
        _nvd_calls.append(time.monotonic())


def lookup_nvd(cve: str) -> ProviderResult:
    cve = cve.upper()
    settings = get_settings()
    ttl = timedelta(hours=settings.nvd_ttl_hours)
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    _nvd_wait()
    try:
        with _client() as client:
            response = client.get(NVD_URL, params={"cveId": cve}, headers=headers)
    except httpx.HTTPError as exc:
        PROVIDER_REQUESTS.labels("nvd", "error").inc()
        raise RetryableError(f"NVD request failed ({type(exc).__name__})") from exc

    if response.status_code in (403, 429, 503):
        PROVIDER_REQUESTS.labels("nvd", "rate_limited").inc()
        retry_after = response.headers.get("retry-after")
        raise RetryableError("NVD rate limit or temporary outage", float(retry_after) if retry_after and retry_after.isdigit() else 35.0)
    if response.status_code != 200:
        PROVIDER_REQUESTS.labels("nvd", "error").inc()
        return ProviderResult("error", "nvd", cve, f"NVD: {cve}", content={"error": f"NVD returned HTTP {response.status_code}"})

    PROVIDER_REQUESTS.labels("nvd", "ok").inc()
    url = f"https://nvd.nist.gov/vuln/detail/{cve}"
    try:
        items = response.json().get("vulnerabilities", [])
    except ValueError:
        return ProviderResult("error", "nvd", cve, f"NVD: {cve}", url, {"error": "NVD returned an unreadable response"})
    if not items:
        return ProviderResult("not_found", "nvd", cve, f"NVD: {cve}", url, {}, ttl=ttl)

    c = items[0].get("cve", {})
    description = next((d.get("value", "") for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    cvss = None
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        metrics = c.get("metrics", {}).get(key)
        if metrics:
            data = metrics[0].get("cvssData", {})
            cvss = {"version": version, "score": data.get("baseScore"), "severity": data.get("baseSeverity") or metrics[0].get("baseSeverity"),
                    "vector": data.get("vectorString")}
            break
    return ProviderResult(
        "found", "nvd", cve, f"NVD: {cve}", url,
        {
            "id": c.get("id"), "status": c.get("vulnStatus"), "published": c.get("published"), "last_modified": c.get("lastModified"),
            "description": description[:1500], "cvss": cvss,
            "cwes": sorted({d.get("value") for w in c.get("weaknesses", []) for d in w.get("description", []) if d.get("value")})[:10],
            "references": [r.get("url") for r in c.get("references", [])[:5] if r.get("url")],
            "cisa_exploit_add": c.get("cisaExploitAdd"),
        },
        ttl=ttl,
    )


# ------------------------------------------------------------------------------ VirusTotal (optional)
_VT_PATH = {"ip": "ip_addresses", "domain": "domains", "md5": "files", "sha1": "files", "sha256": "files", "url": "urls"}
_VT_GUI = {"ip": "ip-address", "domain": "domain", "md5": "file", "sha1": "file", "sha256": "file", "url": "url"}


def vt_supported(indicator_type: str) -> bool:
    return indicator_type in _VT_PATH


def lookup_virustotal(indicator_type: str, value: str) -> ProviderResult:
    """Reputation lookup. Sends only the indicator value. Needs VIRUSTOTAL_API_KEY; untested without one."""
    settings = get_settings()
    title = f"VirusTotal: {value[:80]}"
    ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=") if indicator_type == "url" else value
    try:
        with _client() as client:
            response = client.get(f"{VT_BASE}/{_VT_PATH[indicator_type]}/{ident}", headers={"x-apikey": settings.virustotal_api_key})
    except httpx.HTTPError as exc:
        PROVIDER_REQUESTS.labels("virustotal", "error").inc()
        raise RetryableError(f"VirusTotal request failed ({type(exc).__name__})") from exc

    gui = f"https://www.virustotal.com/gui/{_VT_GUI[indicator_type]}/{ident}"
    if response.status_code == 404:
        PROVIDER_REQUESTS.labels("virustotal", "ok").inc()
        return ProviderResult("not_found", "virustotal", value, title, gui, {}, ttl=timedelta(hours=6))
    if response.status_code == 429:
        PROVIDER_REQUESTS.labels("virustotal", "rate_limited").inc()
        raise RetryableError("VirusTotal rate limit reached", 60.0)
    if response.status_code != 200:
        PROVIDER_REQUESTS.labels("virustotal", "error").inc()
        return ProviderResult("error", "virustotal", value, title, gui, {"error": f"VirusTotal returned HTTP {response.status_code}"})

    PROVIDER_REQUESTS.labels("virustotal", "ok").inc()
    a = response.json().get("data", {}).get("attributes", {})
    return ProviderResult(
        "found", "virustotal", value, title, gui,
        {
            "indicator_type": indicator_type, "last_analysis_stats": a.get("last_analysis_stats"), "reputation": a.get("reputation"),
            "last_analysis_date": a.get("last_analysis_date"), "tags": (a.get("tags") or [])[:10],
            "type_description": a.get("type_description"), "names": ([a["meaningful_name"]] if a.get("meaningful_name") else []),
        },
        ttl=timedelta(hours=6),
    )
