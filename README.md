# 🛡️ ThreatIQ
### AI-Assisted Cybersecurity Alert Investigation & Triage Platform

**Investigate Smarter. Verify the Evidence. Keep Humans in Control.**

ThreatIQ is a multi-tenant cybersecurity platform that centralizes security alert ingestion, threat intelligence enrichment, AI-assisted investigation, analyst review, and auditability.

It helps security teams move from fragmented alert handling to structured, evidence-driven investigations.

> **Core principle:** AI investigates. Analysts decide. Every action is accountable.

---

## 📦 Public Repository

- **Repository:** [ThreatIQ — GitHub](https://github.com/Marvickq/ThreatIQ)
- **License:** See the root-level [`LICENSE`](LICENSE) file.
- **Setup:** [Quick Start — Local Development](#-quick-start--local-development)
- **Deployment:** [`docs/deployment.md`](docs/deployment.md)
- **Documentation:** [`docs/`](docs/)

The repository is publicly accessible for judging, source-code review, and testing.

---

## 🎯 The Problem

Security analysts receive alerts from multiple tools and must manually:

- Collect and correlate security evidence.
- Enrich indicators using threat intelligence.
- Assess vulnerabilities and potential impact.
- Document investigation findings.
- Record decisions and maintain an audit trail.

Fragmented workflows make investigations time-consuming and difficult to standardize.

## 💡 The Solution

ThreatIQ brings these activities into one investigation workflow:

1. **Ingest** — Receive alerts through authenticated webhooks and SIEM integrations.
2. **Normalize** — Validate, normalize, and deduplicate incoming events.
3. **Enrich** — Retrieve relevant threat intelligence.
4. **Investigate** — Generate structured AI-assisted assessments.
5. **Validate** — Check response structure and evidence citations.
6. **Review** — Present findings to security analysts.
7. **Audit** — Preserve investigation activity and decisions.

**ThreatIQ assists investigation; it does not autonomously execute security response actions.**

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🏢 Multi-Tenancy | Organization-level data separation and access control |
| 🔐 Role-Based Access | Owner, administrator, analyst, and viewer roles |
| 📥 Alert Ingestion | Authenticated webhooks and supported SIEM integrations |
| 🔎 Threat Intelligence | Enrichment using CISA KEV, NIST NVD, and VirusTotal |
| 🤖 AI Investigation | Structured assessments through Nebius-hosted inference |
| 🔗 Evidence Validation | Validation of AI citations against stored evidence |
| ⚡ Background Processing | Redis and Celery for asynchronous investigations |
| 📊 Dashboard | Alert metrics, filtering, assignment, and status management |
| 📄 Reports | Downloadable investigation PDF reports |
| 📜 Audit Trail | Traceable investigation activity and analyst decisions |
| 🔄 Live Updates | Server-Sent Events for supported dashboard updates |

---

## 🏗️ System Architecture

```text
       Wazuh / Elastic Security / Webhooks
                       │
                       ▼
              Alert Ingestion
             Validation & Deduplication
                       │
                       ▼
                  FastAPI
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
        PostgreSQL             Redis
        Alert Storage       Job Queue
                                 │
                                 ▼
                           Celery Worker
                                 │
                                 ▼
                       Threat Intelligence
                       CISA / NVD / VirusTotal
                                 │
                                 ▼
                         Evidence Assembly
                                 │
                                 ▼
                       Nebius Token Factory
                         AI Model Inference
                                 │
                                 ▼
                    Schema & Citation Validation
                                 │
                                 ▼
                         Analyst Review
                                 │
                         ┌───────┴───────┐
                         ▼               ▼
                    PDF Reports      Audit Trail
```

### Technology Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js, TypeScript |
| Backend | Python, FastAPI |
| Database | PostgreSQL |
| Background Jobs | Redis, Celery |
| AI Inference | Nebius Token Factory |
| Threat Intelligence | CISA KEV, NIST NVD, VirusTotal |
| SIEM Integrations | Wazuh, Elastic Security |
| Identity | Microsoft Entra ID SSO support |
| Object Storage | AWS S3 |
| Containerization | Docker |
| Infrastructure | Terraform, AWS |
| CI/CD | GitHub Actions |
| Monitoring | Sentry, Prometheus, Grafana |
| Telemetry | OpenTelemetry |

---

## 🤖 NVIDIA & Nebius AI Technology

### Nebius Token Factory

ThreatIQ uses **Nebius Token Factory** for hosted AI model inference in its cybersecurity investigation workflow.

Token Factory enables ThreatIQ to submit alert context and collected evidence for structured AI assessment without operating dedicated model-serving infrastructure.

The workflow uses AI inference to generate:

- Investigation summaries.
- Evidence-based observations.
- AI-generated interpretations.
- Uncertainty and missing-context indicators.
- Recommended next steps for analyst consideration.

### NVIDIA Open-Source Models

NVIDIA model references in the project include:

- **NVIDIA Nemotron**
- **NVIDIA `nv-embed-v1`**

Their exact model identifiers and implemented roles should be documented against the actual application configuration and code. Only claim a model as integrated if the submitted implementation invokes it.

### Where Token Factory Accelerates the Workflow

Token Factory provides hosted inference within the investigation pipeline:

1. ThreatIQ collects and enriches security alert evidence.
2. The backend assembles investigation context.
3. Token Factory provides model inference.
4. ThreatIQ validates the returned structure and evidence citations.
5. Analysts review the resulting assessment.

This lets the project focus on evidence handling, investigation orchestration, validation, and analyst workflows rather than managing model-serving infrastructure.

**Human oversight remains mandatory.** AI-generated findings are advisory, not verified conclusions or automated response actions.

---

## 🔌 Integrations

| Integration | Purpose |
|---|---|
| Wazuh | Security alert ingestion |
| Elastic Security | Security alert ingestion |
| CISA KEV | Known exploited vulnerability information |
| NIST NVD | Vulnerability intelligence |
| VirusTotal | Indicator threat intelligence |
| Nebius Token Factory | Hosted AI inference |
| AWS S3 | Object storage |
| Microsoft Entra ID | SSO support |

External integrations require their respective credentials and configuration.

---

## ⚙️ Quick Start — Local Development

### Prerequisites

- Python
- Node.js and npm
- PostgreSQL
- Redis
- Git
- Required API credentials for enabled integrations

### 1. Clone the repository

```bash
git clone https://github.com/Marvickq/ThreatIQ.git
cd ThreatIQ
```

### 2. Configure environment variables

Use the example environment files provided in the repository, where available.

Configure the required values for:

- PostgreSQL connection
- Redis connection
- Application secret
- Nebius API key, endpoint, and model
- Threat intelligence API credentials
- AWS S3
- Optional SIEM and monitoring integrations

Never commit real credentials or production secrets.

### 3. Start the application

Follow the backend and frontend installation instructions and startup commands documented in the relevant project directories.

For complete, current commands and environment configuration, refer to the repository's setup documentation and deployment guide.

> **Note:** Do not assume that example credentials or placeholder values will connect to external services. Supply valid credentials for the integrations you intend to run.

---

## 🔐 Security & Accountability

ThreatIQ is designed around evidence traceability and human-controlled investigation.

- Backend-enforced authorization and organization-level access checks.
- API key authentication for supported integrations.
- API key expiration and revocation.
- Evidence provenance for threat intelligence results.
- Structured AI response validation.
- Evidence citation validation.
- Audit records for relevant investigation and administrative activity.
- Secrets supplied through environment variables or secret-management services.

### AI Safety

ThreatIQ does not independently:

- Close security alerts based on AI output.
- Isolate endpoints or systems.
- Execute remediation.
- Perform autonomous incident response.

Analysts retain final decision-making authority.

### Known Limitations

- No in-app multi-factor authentication.
- No built-in email delivery or invitations.
- No self-service password reset.
- No record-deletion workflow.
- Tenant isolation is application-level, not database row-level security.
- No billing functionality.
- English-only interface.
- AI investigations may take approximately 25–90 seconds.
- No maintained automated application test suite for the current V2 implementation.
- Microsoft Entra SSO requires tenant-specific configuration and verification.

See [`docs/security.md`](docs/security.md) for additional details.

---

## 🧪 Testing & CI

The current CI workflow includes:

- Code linting.
- Type checking.
- Frontend build verification.
- Packaging checks.

The current V2 implementation does not maintain an automated application test suite. Legacy V1 tests are retained separately under `backend/tests_legacy/` and are not compatible with V2.

Deployment and integration verification should not be confused with automated test coverage.

---

## ☁️ Deployment

ThreatIQ includes Docker and Terraform-based infrastructure configuration for AWS deployment.

Documented deployment components include:

- Frontend application.
- FastAPI backend.
- PostgreSQL.
- Redis.
- Celery workers.
- AWS S3.
- Required external service credentials.
- Monitoring and telemetry integrations.

**Deployment guide:** [`docs/deployment.md`](docs/deployment.md)

Infrastructure configuration does not, by itself, mean that every resource has been provisioned. Deployment must be completed and verified in the target environment.

---

## 📈 Deployment & Integration Milestone

The project team reports that ThreatIQ has been deployed and tested in real-world environments across **10 companies**.

Reported technology and integration scope includes:

- PostgreSQL, Redis, and Celery.
- AWS S3, Docker, Terraform, and AWS.
- GitHub Actions.
- Sentry and OpenTelemetry.
- Prometheus and Grafana.
- Wazuh and Elastic Security.
- VirusTotal.

Supporting project records and documentation are maintained in the repository.

---

## 🗺️ Project Documentation

| Document | Description |
|---|---|
| [`docs/deployment.md`](docs/deployment.md) | Deployment and infrastructure |
| [`docs/integrations.md`](docs/integrations.md) | External integrations |
| [`docs/security.md`](docs/security.md) | Security considerations |
| [`docs/reports.md`](docs/reports.md) | Investigation reports |
| [`docs/dashboard.md`](docs/dashboard.md) | Dashboard documentation |
| [`docs/sso-entra.md`](docs/sso-entra.md) | Microsoft Entra SSO |
| [`wer/`](wer/) | Project requirements and tracking documents |

---

## 🔮 Future Considerations

Potential areas for further development:

- Stronger authentication controls.
- More granular tenant isolation.
- Expanded SIEM and threat intelligence integrations.
- Automated regression testing.
- Additional investigation analytics.
- Improved operational performance measurement.
- Additional language support.

These are future considerations, not claims of existing functionality.

---

## 🏁 Final Note

ThreatIQ brings alert ingestion, threat intelligence enrichment, AI-assisted investigation, evidence validation, analyst review, and auditability into one platform.

It is designed to make security investigations more structured, traceable, and accountable.

**🛡️ ThreatIQ — Investigate Smarter. Verify the Evidence. Keep Humans in Control.**
