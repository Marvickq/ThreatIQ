"""Alert-source adapters (pull model).

Each adapter translates one provider's search API into the normalized `IngestEvent`. Nothing outside
this module knows provider field names.

STATUS: The Wazuh and Elastic adapters follow the providers' documented search APIs (Wazuh indexer /
Elasticsearch `_search`) but have NOT been run against a real Wazuh or Elastic deployment in this
repository's verification - no such instance was available. Treat them as untested until you run
"Test connection" and a manual sync against your own instance.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx

from app.jobs import RetryableError
from app.safe_url import validate_outbound_url
from app.schemas_saas import IndicatorIn, IngestEvent

logger = logging.getLogger(__name__)

PAGE_SIZE = 200


class AdapterError(Exception):
    """A non-recoverable problem (bad credentials, bad configuration). Message is safe to show."""


@dataclass
class FetchResult:
    events: list[IngestEvent]
    checkpoint: dict
    full_page: bool = False
    skipped: int = 0
    notes: list[str] = field(default_factory=list)


# A manual "Test connection" must answer within the UI request budget, even for a black-holed host.
TEST_TIMEOUT = httpx.Timeout(8.0, connect=4.0)


def _post_search(url: str, body: dict, headers: dict, auth: tuple[str, str] | None, verify_tls: bool, timeout: float | httpx.Timeout = 30) -> dict:
    safe = validate_outbound_url(url)
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=verify_tls) as client:
            response = client.post(safe, json=body, headers=headers, auth=auth)
    except httpx.TimeoutException as exc:
        raise RetryableError("The alert source timed out.") from exc
    except httpx.HTTPError as exc:
        raise RetryableError(f"Could not reach the alert source ({type(exc).__name__}).") from exc
    if response.status_code in (401, 403):
        raise AdapterError("The alert source rejected the configured credentials.")
    if response.status_code == 404:
        raise AdapterError("The index or endpoint was not found. Check the endpoint and index pattern.")
    if response.status_code == 429 or response.status_code >= 500:
        raise RetryableError(f"The alert source is unavailable (HTTP {response.status_code}).")
    if response.status_code != 200:
        raise AdapterError(f"The alert source returned HTTP {response.status_code}.")
    try:
        return response.json()
    except ValueError:
        raise AdapterError("The alert source returned an unreadable response.")


def _get(source: dict, path: str, default=None):
    """Read 'a.b.c' from a document that may store it flat ('a.b.c') or nested."""
    if path in source:
        return source[path]
    node = source
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _ip_indicators(*values) -> list[IndicatorIn]:
    return [IndicatorIn(type="ip", value=v) for v in dict.fromkeys(x for x in values if isinstance(x, str) and x)]


class WazuhAdapter:
    kind = "wazuh"
    required_config = ("endpoint",)
    required_credentials = ("username", "password")

    @staticmethod
    def _severity(level: int) -> str:
        return "critical" if level >= 13 else "high" if level >= 10 else "medium" if level >= 7 else "low"

    def fetch(self, config: dict, credentials: dict, checkpoint: dict, limit: int = PAGE_SIZE) -> FetchResult:
        index = config.get("index", "wazuh-alerts-*")
        since = checkpoint.get("last_timestamp") or (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        body = {
            "size": limit,
            "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
            "query": {"bool": {"filter": [
                {"range": {"rule.level": {"gte": int(config.get("min_level", 7))}}},
                {"range": {"@timestamp": {"gte": since}}},
            ]}},
        }
        data = _post_search(
            f"{config['endpoint'].rstrip('/')}/{index}/_search", body, {}, (credentials["username"], credentials["password"]),
            bool(config.get("verify_tls", True)),
        )
        hits = data.get("hits", {}).get("hits", [])
        events, skipped, last = [], 0, since
        for hit in hits:
            src = hit.get("_source", {})
            try:
                level = int(_get(src, "rule.level", 0))
                rule_desc = str(_get(src, "rule.description", "Wazuh alert"))
                agent = _get(src, "agent.name")
                ts = _get(src, "@timestamp") or _get(src, "timestamp")
                events.append(IngestEvent(
                    source="wazuh",
                    external_id=str(src.get("id") or hit.get("_id")),
                    title=rule_desc[:300],
                    description=(f"{rule_desc}\nAgent: {agent or 'unknown'}\nRule: {_get(src, 'rule.id')} (level {level})\n"
                                 f"{str(src.get('full_log', ''))[:3000]}").strip(),
                    severity=self._severity(level),
                    event_time=_parse_time(ts),
                    affected_entity=str(agent)[:256] if agent else None,
                    indicators=_ip_indicators(_get(src, "data.srcip"), _get(src, "data.dstip")),
                    raw=src,
                ))
                last = ts or last
            except (ValueError, KeyError, TypeError):
                skipped += 1
        return FetchResult(events, {"last_timestamp": last}, full_page=len(hits) >= limit, skipped=skipped)

    def test(self, config: dict, credentials: dict) -> str:
        data = _post_search(
            f"{config['endpoint'].rstrip('/')}/{config.get('index', 'wazuh-alerts-*')}/_search",
            {"size": 0, "track_total_hits": True}, {}, (credentials["username"], credentials["password"]),
            bool(config.get("verify_tls", True)), TEST_TIMEOUT,
        )
        total = data.get("hits", {}).get("total", {})
        return f"Connected. The index holds {total.get('value', 'an unknown number of')} documents."


class ElasticAdapter:
    kind = "elastic"
    required_config = ("endpoint",)
    required_credentials = ("api_key",)

    def fetch(self, config: dict, credentials: dict, checkpoint: dict, limit: int = PAGE_SIZE) -> FetchResult:
        index = config.get("index", ".alerts-security.alerts-*")
        since = checkpoint.get("last_timestamp") or (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        body = {
            "size": limit,
            "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
            "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": since}}}]}},
        }
        data = _post_search(
            f"{config['endpoint'].rstrip('/')}/{index}/_search", body, {"Authorization": f"ApiKey {credentials['api_key']}"}, None,
            bool(config.get("verify_tls", True)),
        )
        hits = data.get("hits", {}).get("hits", [])
        events, skipped, last = [], 0, since
        for hit in hits:
            src = hit.get("_source", {})
            try:
                name = str(_get(src, "kibana.alert.rule.name", "Elastic Security alert"))
                host = _get(src, "host.name")
                ts = _get(src, "@timestamp")
                reason = _get(src, "kibana.alert.reason", "")
                events.append(IngestEvent(
                    source="elastic",
                    external_id=str(_get(src, "kibana.alert.uuid") or hit.get("_id")),
                    title=name[:300],
                    description=f"{name}\n{reason}".strip()[:8000],
                    severity=str(_get(src, "kibana.alert.severity", "medium")),
                    event_time=_parse_time(ts),
                    affected_entity=str(host)[:256] if host else None,
                    indicators=_ip_indicators(_get(src, "source.ip"), _get(src, "destination.ip")),
                    raw=src,
                ))
                last = ts or last
            except (ValueError, KeyError, TypeError):
                skipped += 1
        return FetchResult(events, {"last_timestamp": last}, full_page=len(hits) >= limit, skipped=skipped)

    def test(self, config: dict, credentials: dict) -> str:
        data = _post_search(
            f"{config['endpoint'].rstrip('/')}/{config.get('index', '.alerts-security.alerts-*')}/_search",
            {"size": 0, "track_total_hits": True}, {"Authorization": f"ApiKey {credentials['api_key']}"}, None,
            bool(config.get("verify_tls", True)), TEST_TIMEOUT,
        )
        total = data.get("hits", {}).get("total", {})
        return f"Connected. The index holds {total.get('value', 'an unknown number of')} documents."


ADAPTERS = {"wazuh": WazuhAdapter(), "elastic": ElasticAdapter()}
