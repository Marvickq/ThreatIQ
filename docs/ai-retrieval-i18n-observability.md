# AI, retrieval, internationalization and observability

## AI investigation flow
1. Collect evidence: the alert itself, related earlier alerts, and (if allowed) CISA KEV / NVD / VirusTotal results, each stored as an `evidence_items` row.
2. Build a bounded evidence package from those rows (provider *errors* are reported only as `unavailable_sources`).
3. Call the model with a schema-constrained response (`response_format: json_schema`), at most `AI_CONCURRENCY` calls at a time, as a background job with progress.
4. Validate: JSON schema, then **every cited `(source_type, source_id)` must exist in the package**; one retry for invalid output; truncated output fails fast with an actionable message.
5. Persist the assessment with `version`, `prompt_version`, `model_params`, and `evidence_ids` (id, type, status, content hash), so an old assessment can be explained from stored data.
The model separates `observed_facts`, `interpretation`, `missing_information` and `recommended_steps`. It never closes alerts or triggers actions; the human decision is a separate record by a signed-in user.

## Historical retrieval (RAG)
Hybrid retrieval of earlier cases from the **same organization**; full design, limits and evaluation in [rag.md](rag.md). Exact indicator matches (CVE, IP, domain, URL, hashes) rank first, then keyword (PostgreSQL full-text, or a bounded scan on SQLite) and semantic (NVIDIA `nvidia/nemotron-3.5-embed-1b`, pgvector on PostgreSQL) results fused by rank. Stale cases are dropped, analyst-decided cases are preferred, and every case reaches the model with its date, how it was found and its reliability. If embeddings are unavailable the result is keyword + exact and the limitation is passed to the model. Demo incidents still match only demo alerts.


## Internationalization
- Dates, times and numbers use `Intl` with the user's locale and time zone (profile → organization default → browser). Storage is UTC everywhere; the UI shows the zone in use.
- Interface text lives in `frontend/src/i18n/messages.ts` (English only today). To add a language: add a catalog with the same keys, register it in `CATALOGS`, set the locale in a user profile or organization. Missing keys fall back to English. Some labels in newer screens are still literal English strings, not yet extracted to the catalog.

## Observability
- **Logs:** JSON to stdout with `request_id` (also returned as `X-Request-ID` and in error bodies); secrets redacted; jobs log with their IDs.
- **Metrics:** `GET /api/v1/metrics` (Prometheus text; protect with `METRICS_TOKEN`): HTTP rate/latency by route template, AI inference outcomes/latency, provider calls by outcome, jobs by kind/status, queue depth, ingestion outcomes. `ops/` has a Prometheus config, suggested alert rules and a Grafana dashboard.
- **Health:** `/api/v1/health` (liveness), `/api/v1/ready` (database), admin-only `/api/v1/system/status`.
- **Sentry / OpenTelemetry:** off unless `SENTRY_DSN` / `OTEL_EXPORTER_OTLP_ENDPOINT` is set (events are scrubbed through the same redaction). Not exercised against a real Sentry/collector here.
