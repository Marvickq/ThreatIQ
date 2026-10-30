  # 🛡️ ThreatIQ
## AI-Assisted Cybersecurity Alert Investigation & Triage Platform

<p align="center">
  <strong>Investigate Smarter. Verify the Evidence. Keep Humans in Control.</strong>
</p>

<p align="center">
  <em>Multi-Tenant Security Operations · AI-Assisted Investigation · Threat Intelligence · Human-in-the-Loop</em>
</p>



<p align="center">
  <img src="https://img.shields.io/badge/Frontend-Next.js-000000?style=flat-square&logo=nextdotjs" />
  <img src="https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi" />
  <img src="https://img.shields.io/badge/Database-PostgreSQL-4169E1?style=flat-square&logo=postgresql" />
  <img src="https://img.shields.io/badge/AI-Nebius-7C3AED?style=flat-square" />
  <img src="https://img.shields.io/badge/Infrastructure-AWS-FF9900?style=flat-square&logo=amazonaws" />
  <img src="https://img.shields.io/badge/CI%2FCD-GitHub_Actions-2088FF?style=flat-square&logo=githubactions" />
</p>

---

# 📌 1. Executive Summary

**ThreatIQ** is a multi-tenant cybersecurity alert investigation and triage platform designed to help security teams investigate, enrich, assess and document security alerts through a unified workflow.

Security teams receive alerts from multiple sources, including SIEM and endpoint security platforms. Investigating these alerts requires analysts to collect evidence, correlate threat intelligence, understand the context, assess potential impact and record their decisions.

ThreatIQ brings these activities into one platform.

The system receives alerts through authenticated webhooks and SIEM integrations, enriches them using external threat intelligence sources, and uses a hosted AI model to generate structured investigation assessments.

Analysts review the collected evidence and AI-generated findings before making the final decision.

<blockquote>
  🧠 **Core Principle**

  AI investigates. Analysts decide. Every action is accountable.
</blockquote>

## 🎯 1.1 Product Vision

Build an evidence-driven security investigation platform that reduces fragmented alert investigation workflows while preserving analyst control, traceability and organizational data isolation.

## 🚀 1.2 Product Objectives

- 📥 Centralize security alert ingestion from multiple sources.
- 🏢 Provide organization-level access control and tenant isolation.
- 🔎 Enrich alerts with external threat intelligence.
- 🤖 Generate structured, evidence-grounded AI investigation assessments.
- 👨‍💻 Provide analysts with a unified investigation and review interface.
- 📜 Maintain an auditable history of investigations and decisions.
- 📄 Generate downloadable investigation reports.
- ☁️ Support scalable background processing and operational monitoring.

---

# 🔥 2. Problem Statement

Security operations teams work with large volumes of alerts from different security systems.

An alert may require an analyst to:

- Identify the affected asset, user or system.
- Understand the original alert and its severity.
- Collect additional context from security tools.
- Check indicators against threat intelligence providers.
- Review related vulnerabilities and known exploited vulnerabilities.
- Assess the reliability of available evidence.
- Document findings and recommended next steps.
- Record the final analyst decision.

These activities can be distributed across multiple tools and workflows.

## ⚠️ 2.1 Challenges

| Problem | Operational Impact |
|---|---|
| 🔀 Fragmented alert sources | Analysts switch between multiple systems |
| ⏳ Manual enrichment | Additional investigation effort |
| 📝 Inconsistent investigation notes | Difficulties maintaining investigation quality |
| 🤖 Unstructured AI output | Findings may be difficult to verify |
| 🔍 Missing evidence provenance | Reduced investigation traceability |
| 📜 Limited audit visibility | Difficulties reviewing historical decisions |
| 🏢 Organization-level data separation | Requires consistent access enforcement |

## 💡 2.2 Proposed Solution

ThreatIQ provides a centralized investigation workflow combining:

- 📥 Authenticated alert ingestion.
- 🔌 SIEM integrations.
- 🌐 Threat intelligence enrichment.
- 🤖 AI-assisted investigation.
- ✅ Evidence validation.
- 👨‍💻 Human analyst review.
- 📄 Investigation reporting.
- 📜 Audit logging.

**ThreatIQ supports investigation and decision-making. It does not independently execute security response actions.**

---

# 👥 3. Target Users & Roles

## 3.1 Primary Users

| User | Responsibility |
|---|---|
| 🛡️ Security Analyst | Reviews alerts, investigates evidence and records decisions |
| ⚙️ Security Administrator | Manages organization settings, users, API keys and integrations |
| 🏢 Organization Owner | Manages organization-level administration and access |
| 👁️ Read-Only Viewer | Accesses authorized investigation records without administrative permissions |

## 3.2 Role-Based Access

| Role | Permissions |
|---|---|
| Owner | Organization administration and access management |
| Administrator | User management, integrations and configuration |
| Analyst | Alert investigation and analyst decisions |
| Viewer | Read-only access to permitted records |

All authorization decisions must be enforced on the backend rather than relying solely on frontend visibility.

---

# 📦 4. Product Scope

## ✅ 4.1 In Scope

- Multi-tenant organization management.
- Role-based access control.
- API key management.
- Authenticated webhook ingestion.
- Wazuh integration.
- Elastic Security integration.
- Alert deduplication and idempotency.
- Threat intelligence enrichment.
- AI-assisted investigation through Nebius.
- Evidence-backed investigation output.
- Background investigation processing.
- Analyst assignment and review.
- Alert status management.
- Investigation PDF reports.
- Audit logs and export.
- Dashboard metrics and live updates.
- Optional automatic investigation queueing.

## 🚫 4.2 Out of Scope

- Autonomous incident response.
- Automatic alert closure based solely on AI output.
- Automated endpoint isolation or remediation.
- AI replacing security analysts.
- Built-in billing functionality.
- Built-in email delivery and invitations.
- In-app multi-factor authentication.
- Self-service password recovery.

---

# ⚙️ 5. Functional Requirements

## 🔐 Module 1 — Multi-Tenant Identity & Access Management

<badge>Core Module</badge>

**Objective:** Ensure that each organization can manage its users and security investigations independently.

### Features

- Organization-based account structure.
- Owner, administrator, analyst and viewer roles.
- Server-side authorization.
- Organization-level data isolation.
- API key creation and management.
- Configurable API key scopes.
- API key expiration.
- API key revocation.
- Microsoft Entra ID SSO support.

### Workflow

```text
User Authentication
        │
        ▼
Identify Organization
        │
        ▼
Identify User Role
        │
        ▼
Backend Permission Check
        │
        ▼
Authorized Data Access
        │
        ▼
Audit Relevant Operations
```

### Acceptance Criteria

- Users cannot access another organization's records through unauthorized API requests.
- Role permissions are checked server-side.
- Revoked API keys cannot authenticate new requests.
- Expired API keys are rejected.

---

## 📥 Module 2 — Security Alert Ingestion

<badge>Core Module</badge>

**Objective:** Receive security alerts from external systems and normalize them for investigation.

### Input Sources

| Source | Purpose |
|---|---|
| 🔗 Authenticated JSON Webhooks | External alert ingestion |
| 🛡️ Wazuh | SIEM/security alert integration |
| 🔍 Elastic Security | SIEM/security alert integration |

### Functional Requirements

- Accept authenticated webhook requests.
- Validate incoming payloads.
- Normalize supported alert information.
- Support batch ingestion.
- Implement idempotency.
- Deduplicate repeated events.
- Handle out-of-order event arrival.
- Record ingestion failures.
- Maintain integration synchronization information.

### Alert Lifecycle

```text
External Alert
      │
      ▼
Authentication
      │
      ▼
Payload Validation
      │
      ▼
Event Normalization
      │
      ▼
Idempotency & Deduplication
      │
      ▼
Database Persistence
      │
      ▼
Optional Investigation Queue
      │
      ▼
Dashboard Availability
```

### Acceptance Criteria

- Invalid requests are rejected.
- Repeated events do not create unintended duplicate records.
- Valid alerts are associated with the correct organization.
- Integration failures are visible to authorized administrators.

---

## 📊 Module 3 — Alert Management & Dashboard

<badge>Core Module</badge>

**Objective:** Provide a centralized interface for reviewing and managing security alerts.

### Features

- Centralized alert listing.
- Server-side filtering.
- Search and sorting.
- Pagination.
- Alert severity visibility.
- Alert status management.
- Bulk status updates.
- Analyst assignment.
- Database-driven dashboard metrics.
- Live dashboard updates through Server-Sent Events.

### Dashboard Information

| Dashboard Area | Information |
|---|---|
| 🚨 Alert Overview | Total alert metrics |
| 🔴 Severity | Severity distribution |
| 📊 Status | Alert status distribution |
| 🔎 Investigations | Investigation activity |
| 📅 History | Relevant historical records |

### Acceptance Criteria

- Users see only records they are authorized to access.
- Filtering and pagination are handled server-side.
- Dashboard metrics reflect database records.
- Live updates are delivered through the supported event mechanism.

---

## 🌐 Module 4 — Threat Intelligence Enrichment

<badge>Core Module</badge>

**Objective:** Collect additional threat intelligence context before an AI investigation is generated.

### Supported Sources

<details>
<summary><strong>🔎 Threat Intelligence Providers</strong></summary>

| Provider | Purpose |
|---|---|
| CISA KEV | Identify vulnerabilities listed as known exploited |
| NIST NVD | Retrieve vulnerability information |
| VirusTotal | Enrich supported indicators with threat intelligence |

</details>

### Functional Requirements

- Extract supported indicators from alert data.
- Query relevant threat intelligence providers.
- Store enrichment results.
- Preserve source provenance.
- Distinguish confirmed findings from missing matches.
- Distinguish missing matches from provider errors.
- Retain relevant timestamps and investigation context.

### ⚠️ Important Behaviour

A provider returning no matching record must not be interpreted as proof that an indicator is safe.

A provider error must not be represented as a negative threat intelligence finding.

### Acceptance Criteria

- Enrichment results retain their source.
- Provider errors are distinguishable from no-match results.
- AI investigation receives available enrichment evidence.
- Missing enrichment does not become fabricated evidence.

---

## 🤖 Module 5 — AI-Assisted Investigation

<badge>Core Module</badge>

**Objective:** Generate structured investigation assessments using collected alert and threat intelligence evidence.

### AI Infrastructure

- Hosted model inference through Nebius Token Factory.
- Backend-managed investigation workflow.
- Background processing.
- Schema-validated output.
- Evidence citation validation.

### Investigation Pipeline

```text
      SECURITY ALERT
             │
             ▼
      Retrieve Alert Data
             │
             ▼
      Threat Intelligence
        Enrichment
             │
             ▼
       Evidence Assembly
             │
             ▼
      Nebius AI Inference
             │
             ▼
      Structured AI Output
             │
             ▼
      Schema Validation
             │
             ▼
      Citation Validation
             │
             ▼
      Store Investigation
             │
             ▼
       Analyst Review
```

### Expected AI Output

| Component | Description |
|---|---|
| 📌 Executive Summary | Concise explanation of the investigation |
| 📂 Observed Facts | Information directly supported by evidence |
| 🧠 Interpretation | AI-generated assessment of available evidence |
| ⚠️ Uncertainty | Missing context and limitations |
| 🔗 Evidence Citations | References to supporting stored evidence |
| 💡 Recommended Next Steps | Advisory actions for analyst consideration |

### Investigation Reliability Requirements

- AI output must follow the expected response schema.
- Citations must be validated against stored evidence.
- Unsupported citations must not be presented as verified evidence.
- Missing information must remain identifiable.
- Investigation metadata must support reproducibility.
- Failed investigations must be represented as failures rather than successful assessments.

### 🧑‍⚖️ Human-in-the-Loop Requirement

AI output is advisory.

The system must not independently:

- Close an alert.
- Execute endpoint remediation.
- Isolate systems.
- Execute security response actions.

**The analyst retains final decision-making authority.**

---

## ⚡ Module 6 — Optional Automatic Triage

<badge>Optional Feature</badge>

**Objective:** Allow administrators to queue selected incoming alerts for the existing investigation workflow.

### Functional Requirements

- Disabled by default.
- Administrator-controlled configuration.
- Supports newly ingested HIGH and CRITICAL alerts.
- Configurable hourly processing limits.
- Failures are audited.
- Failed jobs are not automatically retried.

### Workflow

```text
New Alert
    │
    ▼
Eligibility Check
    │
    ▼
Processing Limit Check
    │
    ▼
Investigation Queue
    │
    ▼
AI Investigation
    │
    ▼
Analyst Review
```

### Safety Requirements

- Automatic triage must not automatically close alerts.
- AI assessments remain advisory.
- Administrators must be able to control the feature.
- Processing failures must be recorded.

---

## 📄 Module 7 — Investigation Reports

<badge>Reporting</badge>

**Objective:** Generate structured PDF reports from stored investigation records.

### Report Contents

1. 📌 Executive summary.
2. 🚨 Original alert details.
3. 🕒 Alert timeline.
4. 🔎 Threat intelligence evidence.
5. 🤖 Investigation findings.
6. 🔗 Validated AI citations.
7. 👨‍💻 Analyst review and decision.
8. ⚠️ Investigation limitations.
9. 📚 Supporting information.

### Functional Requirements

- Generate PDF reports.
- Use stored investigation records.
- Retain report history.
- Allow authorized users to download reports.
- Enforce alert-level access permissions.

📖 **Documentation:** `docs/reports.md`

---

## 📜 Module 8 — Audit & Accountability

<badge>Security</badge>

**Objective:** Maintain an auditable history of investigation activity and security-relevant actions.

### Audit Events

- Alert ingestion.
- Investigation creation.
- Investigation completion or failure.
- Analyst decisions.
- Administrative changes.
- API key management.
- Alert status changes.
- Report generation and relevant access events.

### Requirements

- Append-only audit timeline.
- Administrative audit logs.
- User or system-process attribution.
- Timestamps.
- Organization association.
- Data export for authorized users.

The audit system must distinguish between AI-generated recommendations and decisions made by human analysts.

---

# 🔄 6. End-to-End Product Workflow

## 6.1 Core Investigation Lifecycle

```text
       📡 EXTERNAL SECURITY SOURCES
       ┌─────────────────────────┐
       │ Wazuh / Elastic / API   │
       │ Authenticated Webhooks  │
       └────────────┬────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │ 📥 Alert Ingestion      │
       │ Validation & Dedup      │
       └────────────┬────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │ 💾 Alert Storage        │
       │ PostgreSQL              │
       └────────────┬────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │ 🌐 Threat Intelligence  │
       │ CISA / NVD / VirusTotal │
       └────────────┬────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │ 🔎 Evidence Assembly    │
       └────────────┬────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │ 🤖 AI Investigation     │
       │ Nebius Hosted Model     │
       └────────────┬────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │ ✅ Schema & Citation    │
       │ Validation              │
       └────────────┬────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │ 👨‍💻 Analyst Review       │
       │ Findings & Evidence     │
       └────────────┬────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │ ⚖️ Final Analyst        │
       │ Decision                │
       └────────────┬────────────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │ 📜 Audit Trail & PDF    │
       │ Investigation Report    │
       └─────────────────────────┘
```

## 6.2 Workflow Principles

- Alert ingestion and investigation are separate operations.
- Enrichment happens before AI assessment.
- AI output is validated before presentation.
- Analyst decisions are stored separately from AI recommendations.
- Relevant operations are recorded in the audit trail.

---

# 🏗️ 7. System Architecture

## 7.1 Architecture Overview

ThreatIQ follows a frontend/backend architecture with asynchronous investigation processing.

| Layer | Technology | Responsibility |
|---|---|---|
| 🎨 Frontend | Next.js, TypeScript | User interface and investigation workflows |
| ⚙️ Backend | Python, FastAPI | API and business logic |
| 💾 Database | PostgreSQL | Application and investigation records |
| 🔄 Background Processing | Redis, Celery | Asynchronous jobs |
| 🧠 AI Inference | Nebius Token Factory | Hosted AI investigation |
| 🌐 Threat Intelligence | CISA KEV, NIST NVD, VirusTotal | Evidence enrichment |
| 🛡️ Security Integrations | Wazuh, Elastic Security | External alert ingestion |
| ☁️ Object Storage | AWS S3 | Object storage |
| 📦 Containerization | Docker | Application packaging |
| 🏗️ Infrastructure | Terraform, AWS | Infrastructure provisioning |
| 🚀 CI/CD | GitHub Actions | Build and delivery workflows |
| 🐛 Error Monitoring | Sentry | Error monitoring |
| 📡 Telemetry | OpenTelemetry | Instrumentation |
| 📊 Metrics | Prometheus, Grafana | Operational metrics and dashboards |

## 7.2 High-Level Architecture

```text
                 👨‍💻 SECURITY ANALYST
                          │
                          ▼
              ┌────────────────────────┐
              │   Next.js Frontend     │
              │   TypeScript UI        │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │    FastAPI Backend     │
              │ Authentication & RBAC  │
              │ Tenant Authorization  │
              └────────────┬───────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
         PostgreSQL      Redis       Integrations
         Database        Queue       Wazuh / Elastic
              │            │            │
              │            ▼            ▼
              │       Celery Worker   Threat Intel
              │            │          CISA / NVD /
              │            ▼          VirusTotal
              │       Nebius AI
              │            │
              └────────────┼────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ Investigation Results │
              │ Evidence Validation   │
              │ Analyst Review        │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ S3 / PDF Reports       │
              │ Audit & Monitoring     │
              └────────────────────────┘
```

## 7.3 Background Processing

Redis and Celery support asynchronous processing.

This is particularly important for AI investigations, which may take approximately **25–90 seconds**.

The frontend should not need to hold a synchronous request open for the entire investigation.

The application supports background investigation jobs and live progress updates.

## 7.4 Infrastructure & Deployment

- ☁️ Terraform manages the documented AWS infrastructure configuration.
- 🐳 Docker provides application containerization.
- 🚀 GitHub Actions performs CI checks, including linting, type checking, frontend build verification and packaging.
- 📊 Sentry, OpenTelemetry, Prometheus and Grafana support operational monitoring.

📖 **Documentation:** `docs/deployment.md`

---

# 🗄️ 8. Data & Information Requirements

## 8.1 Core Data Domains

| Data Domain | Description |
|---|---|
| 🏢 Organizations | Tenant and organization information |
| 👤 Users | User identity and role information |
| 🔑 API Keys | Integration authentication and permissions |
| 🚨 Alerts | Original security events |
| 🔌 Integrations | External security provider configuration |
| 🌐 Enrichment | Threat intelligence results |
| 🤖 Investigations | AI investigation records |
| 📂 Evidence | Supporting investigation information |
| ⚖️ Analyst Decisions | Human review and final decisions |
| 📜 Audit Events | Historical system activity |
| 📄 Reports | Generated investigation documents |

## 8.2 Data Handling Principles

- Tenant ownership must be enforced by the backend.
- API keys must support expiration and revocation.
- Secrets must not be committed to source control.
- AI output must be associated with its supporting evidence.
- Investigation history must be retained according to implemented application behaviour.
- Audit events must preserve attribution.

---

# 🔐 9. Security & Privacy Requirements

## 9.1 Authentication

- Authenticated application access.
- API key authentication for supported integrations.
- Microsoft Entra ID SSO support.
- Server-side permission checks.

## 9.2 Authorization

- Role-based permissions.
- Organization-level data access enforcement.
- Restricted administrative operations.
- Authorized report access.

## 9.3 Infrastructure Security

The documented infrastructure includes:

- AWS-based infrastructure.
- PostgreSQL.
- Redis.
- S3 object storage.
- Docker.
- Terraform.
- Secrets management.
- CI/CD workflows.

## 9.4 Security Limitations

- No in-app MFA.
- No record-deletion workflow.
- No self-service password reset.
- Tenant isolation is application-level rather than database row-level security.
- Microsoft Entra SSO requires tenant-specific configuration and verification.

These limitations must be considered during security reviews and deployment planning.

---

# 📐 10. Non-Functional Requirements

| Category | Requirement |
|---|---|
| 🔐 Security | Server-side authorization and tenant isolation |
| ⚡ Reliability | Idempotent alert ingestion |
| 📜 Traceability | Investigation evidence and audit records |
| 📈 Scalability | Asynchronous processing through Redis and Celery |
| 🧩 Maintainability | Modular backend and documented integrations |
| 📡 Observability | Sentry, OpenTelemetry, Prometheus and Grafana |
| ☁️ Deployment | Docker and Terraform-supported deployment |
| 🎨 Usability | Centralized investigation dashboard |
| 📄 Reporting | PDF reports generated from stored records |
| 🤖 AI Reliability | Schema validation and citation verification |

**Note:** Specific throughput, availability, latency and recovery objectives must be established through measured production data and deployment requirements. They are not assumed in this document.

---

# 🧪 11. Testing & Verification Strategy

## 11.1 Current Testing Status

The current V2 implementation does not maintain an automated application test suite.

Legacy V1 tests are retained in `backend/tests_legacy/` for reference and are not compatible with the V2 API.

### Current CI Coverage

| CI Check | Status |
|---|---|
| Code linting | Included |
| Type checking | Included |
| Frontend build verification | Included |
| Packaging | Included |
| Automated V2 application test suite | Not currently maintained |

## 11.2 Verification Areas

| Area | Verification Focus |
|---|---|
| 🔐 Authentication | Valid and invalid access |
| 🏢 Authorization | Role and organization boundaries |
| 📥 Ingestion | Payload validation and deduplication |
| 🔌 Integrations | Provider connectivity and synchronization |
| 🌐 Enrichment | Confirmed finding, no match and provider error |
| 🤖 AI Investigation | Structured output and citation validation |
| 🔄 Background Jobs | Processing and failure handling |
| 📄 Reports | PDF generation and access control |
| 📜 Audit | Event attribution and history |
| ☁️ Infrastructure | Deployment and service connectivity |

Real-environment deployment and integration verification must be distinguished from automated application test coverage.

---

# 🚀 12. Deployment & Operational Requirements

## 12.1 Deployment Components

- Frontend application.
- FastAPI backend.
- PostgreSQL database.
- Redis.
- Celery background workers.
- AWS S3.
- Terraform-managed infrastructure.
- External AI and threat intelligence credentials.
- Monitoring and telemetry integrations.

## 12.2 External Dependencies

| Service | Purpose |
|---|---|
| Nebius | Hosted AI model inference |
| CISA KEV | Known exploited vulnerability information |
| NIST NVD | Vulnerability intelligence |
| VirusTotal | Indicator enrichment |
| Wazuh | SIEM/security alert integration |
| Elastic Security | SIEM/security alert integration |
| AWS | Infrastructure and object storage |
| Sentry | Error monitoring |
| Prometheus | Metrics |
| Grafana | Metrics visualization |
| OpenTelemetry | Instrumentation |

## 12.3 Environment Configuration

Sensitive configuration must be supplied through environment variables or appropriate secret-management mechanisms.

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
| `SENTRY_DSN` | Error monitoring |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry export |
| Wazuh credentials | Wazuh integration |
| Elastic API key | Elastic Security integration |

⚠️ Never commit real credentials, private keys, database passwords or certificates to the repository.

---

# 📊 13. Product Success Metrics

The following metrics are proposed for ongoing product evaluation. They are not claims of already achieved results.

| Metric | What It Measures |
|---|---|
| 📥 Alert Ingestion Success Rate | Reliability of incoming alert processing |
| 🔁 Duplicate Event Rate | Effectiveness of idempotency and deduplication |
| 🤖 Investigation Completion Rate | Successful completion of queued investigations |
| ⏱️ Investigation Duration | Time from investigation start to completion |
| 🔗 Evidence Citation Validity | Percentage of AI citations validated against stored evidence |
| 🌐 Provider Enrichment Success | Availability of threat intelligence integrations |
| 👨‍💻 Analyst Review Activity | Human review and decision-making activity |
| 📄 Report Generation Success | Reliability of PDF report generation |
| 🔌 Integration Synchronization Health | External integration reliability |
| 📜 Audit Completeness | Coverage of relevant security and investigation events |

Metrics should be measured using actual application and production telemetry.

---

# 🏢 14. Real-World Deployment & Verification

<badge color="success">10-company deployment milestone</badge>

The project team reports that ThreatIQ has been deployed and tested in real-world environments across **10 companies**.

### Reported Deployment & Integration Scope

| Category | Technologies |
|---|---|
| 💾 Database | PostgreSQL |
| 🔄 Background Processing | Redis, Celery |
| ☁️ Object Storage | AWS S3 |
| 📦 Application Packaging | Docker |
| 🏗️ Infrastructure | Terraform, AWS |
| 🚀 CI/CD | GitHub Actions |
| 🐛 Error Monitoring | Sentry |
| 📡 Telemetry | OpenTelemetry |
| 📊 Monitoring | Prometheus, Grafana |
| 🛡️ Security Integrations | Wazuh, Elastic Security |
| 🌐 Threat Intelligence | VirusTotal |

### 📚 Verification References

- `wer/tracker.md`
- `docs/integrations.md`
- `docs/deployment.md`
- `docs/security.md`

The deployment milestone should be supported by the corresponding implementation records and verification evidence.

---

# ⚠️ 15. Known Limitations & Future Considerations

## 15.1 Current Limitations

1. No in-app multi-factor authentication.
2. Microsoft Entra SSO requires tenant-specific configuration and verification.
3. No built-in email delivery or invitations.
4. No self-service password reset.
5. No record-deletion workflow.
6. Tenant isolation is application-level rather than database row-level security.
7. No billing functionality.
8. English-only interface.
9. AI investigation may take approximately 25–90 seconds.
10. No maintained automated application test suite for V2.
11. Competition-specific AI model eligibility requires separate verification.

## 🔮 15.2 Future Product Considerations

These are proposed areas for evaluation, not existing capabilities or committed roadmap items:

- Stronger authentication controls.
- More granular tenant isolation.
- Expanded security integrations.
- Improved automated regression testing.
- Additional investigation analytics.
- More detailed operational service-level objectives.
- Additional language support.
- More comprehensive investigation performance measurement.

---

# 🧭 16. Core Product Principles

### 🔎 1. Evidence Before Conclusions
Investigation findings should be grounded in available evidence.

### 🤖 2. AI as an Assistant, Not an Authority
AI assessments support analysts; they do not replace analyst decisions.

### 🏢 3. Security by Organizational Boundaries
Each organization's data and operations must be protected through backend-enforced authorization.

### 📜 4. Accountability by Design
Investigation activity and decisions must be traceable.

### ⚖️ 5. Operational Transparency
Missing data, provider errors, uncertainty and system limitations must remain visible.

---

# 🏁 17. Final Product Definition

ThreatIQ is an AI-assisted cybersecurity investigation and triage platform that brings alert ingestion, threat intelligence enrichment, evidence-backed AI investigation, human review and auditability into a unified workflow.

It helps security teams move from fragmented alert handling toward structured, traceable investigations.

It does not aim to replace SIEM platforms, eliminate security analysts or autonomously execute incident response.

Its purpose is to make every investigation more structured, evidence-driven and accountable.

---

<p align="center">
  <strong>🛡️ ThreatIQ</strong>
</p>

<p align="center">
  <em>Investigate Smarter. Verify the Evidence. Keep Humans in Control.</em>
</p>

<p align="center">
  🔎 Evidence-Driven · 🤖 AI-Assisted · 👨‍💻 Human-Controlled · 📜 Auditable
</p>
