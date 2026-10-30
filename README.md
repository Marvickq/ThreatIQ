# ThreatIQ

### AI-Assisted Cybersecurity Alert Investigation & Triage

**ThreatIQ** is a multi-tenant cybersecurity alert investigation platform that helps security teams investigate, enrich and assess security alerts through a unified workflow.

Alerts arrive through authenticated webhooks or SIEM integrations, are enriched with threat intelligence, and are assessed by a hosted AI model. Analysts review the evidence, make the final decision and retain full control over the investigation.

**10-company deployment milestone:** ThreatIQ has been deployed and tested in real-world environments across 10 companies, including its infrastructure, monitoring and security integrations.

> **Deployment and verification:** ThreatIQ has been exercised in real environments across 10 companies. PostgreSQL, Redis, Celery, S3, Docker, Terraform/AWS, GitHub Actions, Sentry, OpenTelemetry, Prometheus, Grafana, Wazuh, Elastic Security and VirusTotal integrations have been deployed and tested as part of these environments. Local development and the documented deployment procedures are also available. See `wer/tracker.md`, `docs/integrations.md` and `docs/deployment.md` for implementation and verification details.

---

## What ThreatIQ Does

### 1. Multi-Tenant Access & Security
- Organization-based access with owner, administrator, analyst and read-only viewer roles.
- Server-side authorization and per-organization data isolation.
- API keys with configurable scopes, expiry and revocation.
- Microsoft Entra ID single sign-on support.

### 2. Security Alert Management
- Centralized alert ingestion and investigation.
- Server-side search, filtering, sorting and pagination.
- Bulk status updates and analyst assignment.
- Live dashboard updates through Server-Sent Events.
- Database-driven dashboard metrics and charts.

### 3. Alert Ingestion & SIEM Integrations
- Authenticated JSON webhook ingestion.
- Idempotency, deduplication, batch ingestion and out-of-order event handling.
- Wazuh and Elastic Security pull integrations.
- Integration health, last synchronization, error reporting and manual sync.

### 4. Threat Intelligence Enrichment
- CISA Known Exploited Vulnerabilities (KEV).
- NIST National Vulnerability Database (NVD).
- VirusTotal integration.
- Distinguishes between a confirmed finding, no matching record and provider errors.
- Stores source provenance alongside enrichment results.

### 5. AI-Assisted Investigation
- Gathers available evidence before AI assessment.
- Uses a hosted AI model through Nebius.
- Produces schema-validated investigation output.
- Validates every AI citation against stored evidence.
- Separates observed facts, interpretation, uncertainty and recommended next steps.
- Stores reproducibility metadata for investigation runs.
- Supports background investigation jobs with live progress updates.

**Human-in-the-loop by design:** AI provides recommendations. It does not independently close alerts or execute security response actions.

### 6. Optional Automatic Triage
- Administrator-controlled and disabled by default.
- Can queue newly ingested HIGH and CRITICAL alerts for the existing investigation workflow.
- Uses configurable hourly processing limits.
- Failures are audited and are not automatically retried.
- AI assessments remain advisory; analysts retain decision-making authority.

### 7. Investigation Reports
Generates professional PDF investigation reports containing:
- Executive summary.
- Alert details and timeline.
- Evidence and threat intelligence.
- AI investigation findings with validated citations.
- Analyst review and decision.
- Limitations and supporting information.

Reports are generated from stored records, retained with their history and downloadable by users authorized to read the alert.

See `docs/reports.md`.

### 8. Human Review & Auditability
- Analyst decisions are recorded separately from AI recommendations.
- Append-only audit timeline.
- Administrative audit logs.
- Data export.
- Security-relevant actions are attributed to the responsible user or system process.

---

## Architecture & Technology Stack

| Layer | Technologies |
|---|---|
| Frontend | Next.js, TypeScript |
| Backend | Python, FastAPI |
| Database | PostgreSQL |
| Background processing | Redis, Celery |
| Vector / retrieval capabilities | See current retrieval implementation documentation |
| AI inference | Nebius Token Factory |
| Threat intelligence | CISA KEV, NIST NVD, VirusTotal |
| Security integrations | Wazuh, Elastic Security |
| Identity | Microsoft Entra ID |
| Object storage | AWS S3 |
| Containerization | Docker |
| Infrastructure as Code | Terraform, AWS |
| CI/CD | GitHub Actions |
| Error monitoring | Sentry |
| Telemetry | OpenTelemetry |
| Metrics & dashboards | Prometheus, Grafana |

---

## Deployment & Real-World Testing

ThreatIQ has been deployed and tested across **10 company environments**.

The deployment and integration scope includes:

- PostgreSQL database infrastructure.
- Redis and Celery background processing.
- S3-based object storage.
- Docker-based application environments.
- Terraform-managed AWS infrastructure.
- GitHub Actions CI/CD workflows.
- Sentry error monitoring.
- OpenTelemetry instrumentation.
- Prometheus metrics collection.
- Grafana monitoring dashboards.
- Wazuh and Elastic Security integrations.
- VirusTotal threat intelligence integration.

The project also maintains local development instructions, deployment documentation, infrastructure configuration and rollback guidance.

For detailed implementation and integration verification, refer to:
- `docs/deployment.md`
- `docs/integrations.md`
- `docs/security.md`
- `wer/tracker.md`

---

## Quick Start — Local Development

### Prerequisites
- Python 3.13
- Node.js and npm
- Git

### 1. Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd ThreatIQ
```

### 2. Set up the backend

```powershell
cd backend

py -3.13 -m venv .venv

.venv\Scripts\python -m pip install -r requirements.txt

copy .env.example .env.local
```

Configure the required environment variables, including your Nebius API credentials.

For sample alerts, configure:

```env
ALLOW_DEMO_DATA=true
```

Start the backend:

```powershell
.venv\Scripts\python -m uvicorn app.main:app --port 8000
```

### 3. Set up the frontend

Open a second terminal:

```powershell
cd frontend

npm install

npm run dev
```

Open the application:

- Frontend: http://localhost:5173
- API documentation: http://localhost:8000/api/v1/docs

Register an organization and configure API keys and integrations under **Settings**.

For Docker, AWS/Terraform deployment, database migrations and rollback instructions, see `docs/deployment.md`.

---

## Documentation

| Document | Description |
|---|---|
| `docs/deployment.md` | Local development, Docker Compose, AWS/Terraform deployment, verification and rollback |
| `docs/reports.md` | PDF investigation reports, API, contents and permissions |
| `docs/dashboard.md` | Security overview, endpoints, filters, metrics and refresh behaviour |
| `docs/sso-entra.md` | Microsoft Entra ID SSO flow, mapping rules and setup |
| `docs/security.md` | Authentication, roles, tenant isolation and data handling |
| `docs/integrations.md` | Integration setup, credentials, capabilities and verification |
| `docs/ai-retrieval-i18n-observability.md` | AI workflow, retrieval, localization and observability |
| `backend/.env.example` | Backend configuration template |
| `.env.compose.example` | Docker Compose configuration template |
| `wer/` | PRD, technical specification, schema, design and implementation tracker |

---

## Environment Variables & External Services

| Variable / Service | Purpose |
|---|---|
| `NEBIUS_API_KEY` | Hosted AI model authentication |
| `NEBIUS_BASE_URL` | Nebius API endpoint |
| `NEBIUS_MODEL` | Configured AI model |
| `SECRET_KEY` | Application security |
| PostgreSQL URL | Production database connection |
| `NVD_API_KEY` | Optional NVD API authentication |
| `VIRUSTOTAL_API_KEY` | VirusTotal integration |
| `REDIS_URL` | Redis connection |
| `S3_BUCKET` | AWS object storage |
| `SENTRY_DSN` | Sentry error monitoring |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry export |
| Wazuh credentials | Wazuh integration |
| Elastic API key | Elastic Security integration |

AWS deployment additionally requires an AWS account, VPC, ACM certificate and container registry.

**Never commit real credentials, API keys, database passwords or private certificates to the repository.**

---

## Testing & CI

The current V2 implementation does not maintain an automated application test suite. Legacy V1 tests are retained in `backend/tests_legacy/` for reference and are not compatible with the V2 API.

The GitHub Actions CI workflow (`.github/workflows/ci.yml`) performs:
- Linting.
- Type checking.
- Frontend build verification.
- Packaging.

It does not currently run an automated application test suite.

Real-environment deployment and integration verification are documented separately from automated test coverage.

---

## Known Limitations

- No in-app multi-factor authentication.
- Microsoft Entra SSO requires tenant-specific configuration and verification.
- No built-in email delivery, invitations or self-service password reset.
- Account recovery is performed using `python -m app.cli reset-password`.
- No record-deletion workflow.
- Tenant isolation is application-level rather than database row-level security.
- No billing functionality.
- Interface currently supports English only.
- Competition-specific AI model eligibility must be checked against the applicable rules.
- AI investigation can take approximately 25–90 seconds.

---

## Core Design Principle

**AI investigates. Analysts decide. Every action is accountable.**

ThreatIQ is designed to make security investigations more structured, evidence-driven and auditable without removing human judgment from security operations.
