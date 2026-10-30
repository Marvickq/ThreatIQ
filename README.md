# ThreatIQ

A multi-tenant cybersecurity alert investigation platform. Alerts arrive through authenticated webhooks or SIEM pulls, are enriched with threat intelligence, assessed by a hosted AI model, and decided by a human analyst. The AI only advises; it never closes alerts or takes response actions, and every decision, status change and security-relevant action is attributed and audited.

> **Read first — what is and is not verified.** The application was exercised end to end on SQLite with real calls to Nebius, CISA KEV and NIST NVD, in a real browser. PostgreSQL, Redis, Celery, S3, Docker, Terraform/AWS, GitHub Actions, Sentry/OpenTelemetry/Prometheus/Grafana, and the Wazuh, Elastic and VirusTotal integrations are **written but were never run against the real thing**. Nothing here claims a cloud deployment exists. Details: `wer/tracker.md`, `docs/integrations.md`.

## What it does
- **Organizations and roles** (owner, administrator, analyst, read-only viewer) with server-side authorization and per-organization data isolation; API keys with scopes, expiry and revocation.
- **Alerts:** server-side search, filters, sorting, pagination, bulk status changes, assignment, live updates (Server-Sent Events), dashboard metrics and charts computed from the database.
- **Ingestion:** generic JSON webhook (idempotent, deduplicating, out-of-order safe, batch), plus Wazuh and Elastic Security pull adapters, each with health, last sync, errors and manual sync.
- **Threat intelligence:** CISA KEV and NVD (real, tested), VirusTotal (optional, untested); found / no record / provider error kept distinct; provenance stored.
- **AI investigation:** evidence gathered first, schema-validated output, every citation checked against stored evidence, facts/interpretation/uncertainty/steps separated, reproducibility metadata stored, runs as a background job with live progress.
- **Automatic triage (opt-in, off by default):** when an administrator enables it, new HIGH and CRITICAL ingested alerts are queued for the existing background analysis job (never inside the ingest request). Capped by `AUTO_TRIAGE_MAX_PER_HOUR` and the shared `RATE_LIMIT_AI_PER_HOUR`; failures are audited and not auto-retried; the AI still only advises. Not yet run against a real queue/worker.
- **Investigation reports:** a professional PDF per alert (cover, executive summary, evidence and threat intelligence, AI investigation with checked citations, analyst review, timeline, limitations), generated on the server from stored records, kept with its history, and downloadable by anyone who can read the alert. See `docs/reports.md`.
- **Human review and audit:** decisions by named reviewers, separate from AI recommendations; append-only audit timeline; admin audit log; data export.

## Quick start (local)
```powershell
cd backend
py -3.13 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
copy .env.example .env.local        # add NEBIUS_* for AI; ALLOW_DEMO_DATA=true for sample alerts
.venv\Scripts\python -m uvicorn app.main:app --port 8000

cd ..\frontend
npm install
npm run dev                          # http://localhost:5173
```
Register an organization, then Settings → API keys / Integrations. Full instructions, Docker Compose, AWS/Terraform, migrations and rollback: **`docs/deployment.md`**.

## Documentation
| | |
|---|---|
| `docs/deployment.md` | local development, migrations, Docker Compose, AWS/Terraform, verification, rollback |
| `docs/reports.md` | PDF investigation reports: API, contents, permissions, what is and is not verified |
| `docs/dashboard.md` | the Security overview: endpoints, filters, real-vs-demo separation, UTC handling, refresh behaviour |
| `docs/sso-entra.md` | Microsoft Entra ID single sign-on: flow, mapping rules, manual setup, what is unverified |
| `docs/security.md` | authentication, roles, isolation, data handling, account recovery, limits |
| `docs/integrations.md` | every integration, the credentials each needs, and what was tested |
| `docs/ai-retrieval-i18n-observability.md` | AI flow, retrieval (exact indicators; no embeddings), i18n, metrics/logs |
| `backend/.env.example`, `.env.compose.example` | configuration (placeholders only) |
| `wer/` | PRD, TechSpec, Schema, Design, WebsiteFlow, Rules, ImplementationPlan, Tracker |
| API reference | `GET /api/v1/docs` (OpenAPI) on a running server |

## Credentials and external services needed
`NEBIUS_API_KEY` / `NEBIUS_BASE_URL` / `NEBIUS_MODEL` (AI) · `SECRET_KEY` and a PostgreSQL URL (production) · optional `NVD_API_KEY`, `VIRUSTOTAL_API_KEY`, `REDIS_URL`, `S3_BUCKET`, `SENTRY_DSN`, `OTEL_EXPORTER_OTLP_ENDPOINT` · Wazuh indexer credentials / Elastic API key per integration (entered in the UI, stored encrypted) · for AWS: an account, VPC, ACM certificate, container registry.

## Testing
No automated test suite is maintained: this version was built under an instruction not to implement automated testing. The V1 tests are kept in `backend/tests_legacy/` for reference only and do not run against the V2 API. CI (`.github/workflows/ci.yml`) lints, type-checks, builds and packages; it runs no tests.

## Known limitations
No in-app MFA, no live-tenant verification of Entra SSO yet (see `docs/sso-entra.md`), no email (so no invitations or self-service password reset; recovery is `python -m app.cli reset-password`); no semantic/embedding retrieval; no record-deletion workflow; tenant isolation is application-level (no row-level security); no billing (out of scope); only English interface text; the AI model's competition eligibility is unverified; AI analysis takes 25–90 s.
