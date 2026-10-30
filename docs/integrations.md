# Integrations and external credentials

What needs credentials, what was actually tested, and how to set each one up.

## Summary

| Integration | Needs | Status in this repository |
|---|---|---|
| **Nebius Token Factory** (AI) | `NEBIUS_API_KEY`, `NEBIUS_BASE_URL`, `NEBIUS_MODEL` | **Tested against the real service** (structured output, async job, UI) |
| **CISA KEV** | nothing (public catalog) | **Tested against the real service** |
| **NIST NVD** | nothing; `NVD_API_KEY` optional (higher rate limit) | **Tested against the real service**; an org admin must opt in |
| **Generic JSON webhook** | an API key with scope `ingest:write` | **Tested** (dedup, idempotency, batch, out-of-order) |
| **Wazuh** (indexer search) | endpoint + indexer username/password | Adapter written; **NOT tested against a real Wazuh** (only against a local stand-in server that mimics the response shape) |
| **Elastic Security** | endpoint + API key | Adapter written; **NOT tested against a real Elastic** |
| **VirusTotal** | `VIRUSTOTAL_API_KEY` + org opt-in | Provider written; **NOT tested** (no key available) |
| **STIX/TAXII** | — | **Not implemented** |
| **PostgreSQL / Redis / Celery / S3 / ECS / Terraform** | see `deployment.md` | Written; **not run** (not available where this was built) |
| **Sentry / OpenTelemetry** | `SENTRY_DSN` / `OTEL_EXPORTER_OTLP_ENDPOINT` | Wired and inert until configured; **not exercised** |
| **Clerk / Auth.js / OIDC** | — | **Not implemented.** ThreatIQ uses its own backend authentication (Argon2id passwords, server-side sessions). |
| **Email (invitations, reset)** | — | **Not implemented.** No email delivery is configured, so there are no invitations and no self-service reset. |

An integration shows **Connected** only after a sync or event actually succeeded. Otherwise the UI says *Not configured*, *Configured, never synced*, *Waiting for first event* or *Error*.

## Nebius Token Factory (AI)
1. Create an API key in your Nebius Token Factory account.
2. `NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1` (from the Nebius docs).
3. Get the exact model ID from `GET {base}/models` with your key. It must match exactly (for example `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`; the name without `NVIDIA-` is not in the catalogue).
4. The model is a reasoning model: analysis takes roughly 25–90 s and reasoning tokens count toward `NEBIUS_MAX_TOKENS` (default 12000). If a response is cut off the job fails with an actionable message instead of retrying.
5. Whether this model satisfies any competition/eligibility rule is **not verified** here; check the official rules.

## Generic JSON webhook
1. Settings → API keys → create a key with the `ingest:write` scope (shown once).
2. Send events:
```bash
curl -X POST https://YOUR-HOST/api/v1/ingest/webhook \
  -H "Authorization: Bearer tiq_xxxxxxxx_..." \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: <unique per delivery>" \
  -d '{"source":"my-siem","external_id":"evt-123","title":"Suspicious login",
       "severity":"high","event_time":"2026-10-28T09:00:00Z","affected_entity":"web-01",
       "description":"...","indicators":[{"type":"ip","value":"203.0.113.9"}],"raw":{}}'
```
Fields: `source` (`[A-Za-z0-9_.-]`, ≤64), `external_id` (≤256), `title` (≤300), `severity` (`low|medium|high|critical`, or `info/warning/error/fatal/...`), optional `event_time` (ISO-8601; naive = UTC), `description`, `affected_entity`, `indicators` (≤100; types `ip, domain, url, md5, sha1, sha256, cve, account, host`), `raw` (preserved verbatim, treated as untrusted).

Responses: `201` new alert, `200` duplicate/update, `401` bad key, `403` key lacks the scope, `422` invalid, `413` too large, `429` rate limited.
Deduplication, in order: exact replay (same source+id+time, or same `Idempotency-Key`) is a no-op; same source+id at another time is an update (latest wins; late events never overwrite newer data); a different id with the same detection (source+title+entity) on an unresolved alert within 24 h attaches to that alert and can only raise severity.
Batches: `POST /api/v1/ingest/webhook/batch` with `{"events":[...]}` (≤500) returns `202` and a job ID; the same `Idempotency-Key` returns the same job.

## Wazuh
ThreatIQ reads the **Wazuh indexer** (OpenSearch) `wazuh-alerts-*` index with a `_search` call.
Settings → Integrations → Add → Wazuh: endpoint (e.g. `https://wazuh-indexer:9200`), indexer username and password, optional `min_level` (default 7) and `poll_interval_seconds` (default 300, minimum 60).
Level mapping: ≥13 critical, 10–12 high, 7–9 medium, else low. Use *Test connection*, then *Sync now*. **Run these yourself: the adapter has not been tried against a real Wazuh.**

## Elastic Security
Reads `.alerts-security.alerts-*` from Elasticsearch with an API key (`Authorization: ApiKey <base64 id:key>`). Create a key restricted to read on that index. Same Test/Sync flow. **Not tested against a real Elastic.**

### Endpoint rules (SSRF protection)
Loopback, link-local (including `169.254.169.254`), multicast and reserved addresses are always refused. Private ranges (10/8, 172.16/12, 192.168/16) are refused in production unless `ALLOW_PRIVATE_INTEGRATION_ENDPOINTS=true` (on-premise SIEMs). Redirects are not followed. Also restrict egress at the network layer.

## Threat intelligence
- **CISA KEV:** the full catalog is downloaded and cached (`KEV_TTL_HOURS`, default 24); nothing about your alerts is sent. A failed refresh falls back to the last good copy and is shown as stale.
- **NIST NVD:** per-CVE lookups of **CVE IDs only**, respecting NVD's rate limits (5/30 s, 50/30 s with a key). Off until an org admin enables *Allow lookups with external providers* (with a confirmation that explains what is sent).
- **VirusTotal:** indicator values (IP/domain/URL/hash) only, never alert text; needs the key **and** the org opt-in.
- Results are stored with source URL, provider ID, retrieval time, expiry and a content hash. **Found**, **No record** and **Provider error** are different outcomes, and "no record" is never described as "safe".
- Respect each provider's terms and rate limits; set `NVD_API_KEY` for production use.
