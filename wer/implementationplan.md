# ThreatIQ — Implementation Plan

## 1. Objective

Build ThreatIQ, an AI-powered cybersecurity investigation assistant that helps analysts understand security alerts, review supporting evidence, compare historical incidents, and record human decisions.

The implementation must deliver a working end-to-end flow:

**Alert → AI Investigation → Evidence → Human Review → Audit History**

The MVP must use a real inference call through Nebius Token Factory with an eligible NVIDIA open model, in line with the project's intended hackathon stack. Verify the final competition rules and model availability before submission.

### Success criteria

- Analysts can browse and filter synthetic security alerts.
- An analyst can open an alert and request an AI assessment.
- The AI assessment includes a summary, suggested classification, evidence, missing information, and recommended next steps.
- The application persists assessments in the database.
- Analysts can submit and persist a human decision.
- The application displays investigation history.
- The application handles model failures without fabricating results.
- The complete demo runs reliably from a clean setup.

---

## 2. Technology Stack

| Layer | Technology | Responsibility |
|---|---|---|
| Frontend | React + TypeScript | Dashboard and investigation interface |
| Styling | Tailwind CSS | Responsive styling and shared design tokens |
| Backend | FastAPI | REST API and application logic |
| Validation | Pydantic | Request and response validation |
| ORM | SQLModel / SQLAlchemy | Database models and queries |
| Database | SQLite | MVP persistence |
| Migrations | Alembic | Database schema changes |
| AI inference | Nebius Token Factory | Model API calls |
| AI model | Eligible NVIDIA open model, e.g. Nemotron | Security-alert assessment |
| Historical retrieval | ChromaDB | Similar-incident retrieval |
| External intelligence | Tavily, optional | Public threat-intelligence search |
| Testing | Pytest | Backend and service tests |

Keep the backend API key on the server. Never expose it in frontend code or browser requests.

---

## 3. Repository Structure

```text
threatiq/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Header.tsx
│   │   │   ├── AlertTable.tsx
│   │   │   ├── SeverityBadge.tsx
│   │   │   ├── AssessmentPanel.tsx
│   │   │   ├── EvidenceSection.tsx
│   │   │   ├── ReviewForm.tsx
│   │   │   └── HistoryTimeline.tsx
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   └── Investigation.tsx
│   │   ├── services/
│   │   │   └── api.ts
│   │   ├── types/
│   │   │   └── index.ts
│   │   ├── App.tsx
│   │   └── main.tsx
│   └── package.json
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── schemas.py
│   │   ├── routers/
│   │   │   ├── alerts.py
│   │   │   ├── investigations.py
│   │   │   ├── decisions.py
│   │   │   └── history.py
│   │   ├── services/
│   │   │   ├── alert_service.py
│   │   │   ├── investigation_service.py
│   │   │   ├── evidence_service.py
│   │   │   ├── retrieval_service.py
│   │   │   ├── threat_intel_service.py
│   │   │   ├── review_service.py
│   │   │   └── audit_service.py
│   │   └── ai/
│   │       ├── nebius_client.py
│   │       ├── prompts.py
│   │       └── response_parser.py
│   ├── data/
│   │   ├── alerts.json
│   │   └── incidents.json
│   ├── tests/
│   ├── requirements.txt
│   └── .env.example
├── docs/
│   ├── PRD.md
│   ├── TechSpec.md
│   ├── WebsiteFlow.md
│   ├── Design.md
│   ├── Schema.md
│   └── ImplementationPlan.md
├── .gitignore
└── README.md
```

Keep the implementation modular, but do not spend hackathon time creating empty files or abstractions that are not yet needed.

---

## 4. Implementation Phases

## Phase 0 — Environment and Project Setup

**Priority:** P0

### Tasks

1. Create the repository structure.
2. Initialize the React + TypeScript frontend.
3. Create the FastAPI backend.
4. Install the required dependencies.
5. Configure environment variables.
6. Initialize SQLite and create database tables.
7. Add a health-check endpoint.
8. Add synthetic alert and historical-incident data.
9. Verify the frontend and backend start independently.

### Environment variables

```env
APP_ENV=development
APP_HOST=127.0.0.1
APP_PORT=8000

DATABASE_URL=sqlite:///./threatiq.db

NEBIUS_API_KEY=
NEBIUS_BASE_URL=
NEBIUS_MODEL=

TAVILY_API_KEY=
ENABLE_EXTERNAL_SEARCH=false
ENABLE_HISTORICAL_RETRIEVAL=true

FRONTEND_ORIGIN=http://localhost:5173
```

Use the official Nebius documentation for the current API base URL, authentication format, and supported model identifier. Do not guess these values.

### Completion criteria

- [ ] Frontend starts successfully.
- [ ] Backend starts successfully.
- [ ] `GET /api/v1/health` returns a successful response.
- [ ] Database tables are created.
- [ ] Synthetic alerts can be loaded.
- [ ] Secrets are excluded from Git.

---

## Phase 1 — Database and Alert Dashboard

**Priority:** P0

### Tasks

1. Implement the `SecurityAlert` model.
2. Implement the `Assessment` model.
3. Implement the `ReviewDecision` model.
4. Implement the `AuditEvent` model.
5. Configure foreign keys and indexes.
6. Seed synthetic alerts.
7. Implement the alert-list API.
8. Build the dashboard UI.
9. Connect the dashboard to the backend.

### Required endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/health` | Check backend availability |
| `GET` | `/api/v1/alerts` | List alerts |
| `GET` | `/api/v1/alerts/{alert_id}` | Retrieve alert details |

The alert-list endpoint should support useful filtering, such as severity, workflow status, and text search.

### Dashboard UI

Include:
- Alert summary metrics.
- Search and filters.
- Alert table.
- Severity indicators.
- Investigation status.
- A way to open an alert.

Follow `Design.md`: dark background, restrained red accents, clear typography, sharp geometry, and minimal decoration.

### Completion criteria

- [ ] The dashboard displays actual database records.
- [ ] Search and filtering work.
- [ ] Clicking an alert opens its investigation page.
- [ ] Empty and loading states are implemented.
- [ ] Invalid alert IDs return a clear error.

---

## Phase 2 — Real AI Investigation

**Priority:** P0 — core differentiator

### Tasks

1. Configure the Nebius Token Factory client.
2. Select an eligible NVIDIA open model.
3. Implement the system prompt.
4. Pass the alert and available evidence to the model.
5. Parse and validate the model response.
6. Save successful assessments in SQLite.
7. Record assessment success or failure in the audit history.
8. Display the assessment on the investigation page.

### Required endpoint

`POST /api/v1/alerts/{alert_id}/analyze`

The endpoint should:

1. Validate the alert ID.
2. Retrieve the alert and available evidence.
3. Prepare a bounded, structured model request.
4. Call the configured model.
5. Parse and validate the result.
6. Persist the assessment.
7. Record an audit event.
8. Return the assessment to the frontend.

### Assessment response

The assessment should contain:

```json
{
  "summary": "Plain-language assessment of the alert.",
  "suggested_classification": "needs_review",
  "evidence": [],
  "missing_information": [],
  "recommended_steps": []
}
```

This is an illustrative response shape. The actual response must conform to the Pydantic schema implemented in the backend.

Allowed classification values:

- `likely_true_positive`
- `likely_false_positive`
- `needs_review`

### AI behavior requirements

The model must:
- Separate observed facts from interpretations.
- Reference the evidence supporting its assessment.
- Identify missing information.
- Explain uncertainty.
- Recommend investigation steps rather than executing them.
- Avoid inventing sources, incidents, or technical indicators.

Retrieved text and alert descriptions must be treated as untrusted input, not as instructions to the model.

### Error handling

Handle:
- Missing or invalid API credentials.
- Unsupported model identifiers.
- API timeouts.
- Rate limits.
- Invalid model output.
- Empty responses.
- Database persistence failures.

A failed model call must not create a fake successful assessment. Return a clear error and retain an appropriate failure event where possible.

### Completion criteria

- [ ] A real model call succeeds.
- [ ] The assessment follows the required schema.
- [ ] The assessment is saved in the database.
- [ ] The frontend displays the saved assessment.
- [ ] Errors are visible and recoverable.
- [ ] Reopening the page does not lose persisted assessments.

---

## Phase 3 — Evidence and Historical Retrieval

**Priority:** P0 for basic evidence; P1 for ChromaDB and external search

### Tasks

1. Implement an evidence service.
2. Identify evidence contained in the original alert.
3. Load the synthetic historical incidents.
4. Implement similar-incident retrieval.
5. Optionally add ChromaDB.
6. Optionally integrate Tavily for public threat intelligence.
7. Connect retrieved evidence to the assessment.
8. Display evidence sources in the UI.

### Minimum viable implementation

Before adding vector search, retrieve a few relevant synthetic incidents using simple matching or filtering. This provides a working evidence-based flow without unnecessary setup.

Add ChromaDB only after the basic investigation works.

### Evidence requirements

Each evidence item should contain, where available:
- Source type.
- Source identifier.
- Description.
- Timestamp.
- Source URL for external information.
- Retrieval timestamp for external information.

The application must distinguish:

1. Facts directly present in the alert.
2. Related historical incidents.
3. Information retrieved from public sources.
4. Model-generated interpretations.

Do not display an external source as consulted if the application did not actually retrieve it.

### Completion criteria

- [ ] The assessment uses available alert evidence.
- [ ] Relevant historical incidents can be displayed.
- [ ] Evidence references remain linked to their source.
- [ ] Missing evidence is represented honestly.
- [ ] Optional retrieval failures do not break the core investigation.

---

## Phase 4 — Human Review and Audit History

**Priority:** P0

### Tasks

1. Implement decision validation.
2. Create the decision submission endpoint.
3. Persist each review decision.
4. Update the alert workflow status when appropriate.
5. Record audit events.
6. Implement the history endpoint.
7. Build the review form.
8. Build the history timeline.
9. Test repeated reviews.

### Required endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/v1/alerts/{alert_id}/decisions` | Record a human decision |
| `GET` | `/api/v1/alerts/{alert_id}/history` | Retrieve investigation history |

### Review options

- `true_positive`
- `false_positive`
- `needs_further_review`

The reviewer may add a note.

### Review workflow

1. The analyst reads the original alert.
2. The analyst reviews the AI assessment and evidence.
3. The analyst selects a decision.
4. The application validates the decision.
5. The application saves the decision.
6. The application records the corresponding audit event.
7. The UI confirms the saved decision and refreshes the history.

### Important rules

- AI assessments and human decisions must remain separate.
- New reviews must not overwrite older decisions.
- The decision must reference an assessment belonging to the same alert when an assessment ID is provided.
- Never automatically block an account, close an alert, or execute a destructive response.

### Completion criteria

- [ ] All three review options work.
- [ ] Optional notes are persisted.
- [ ] Decisions remain available after a page refresh.
- [ ] Earlier decisions remain in the history.
- [ ] Audit events show relevant changes.
- [ ] The UI distinguishes the latest human decision from the AI recommendation.

---

## Phase 5 — Product Design and UX Polish

**Priority:** P0 for usability; advanced visual effects are secondary

### Tasks

1. Apply shared color and typography tokens.
2. Refine the dashboard layout.
3. Refine the investigation layout.
4. Style severity and workflow indicators.
5. Improve evidence readability.
6. Add loading, empty, and error states.
7. Verify mobile layouts.
8. Add keyboard focus states.
9. Respect reduced-motion preferences.
10. Remove placeholder content that could be mistaken for real data.

### Visual hierarchy

The investigation page should answer four questions quickly:

1. What happened?
2. What evidence supports the assessment?
3. What information is missing?
4. What decision did the human analyst make?

Do not spend time implementing the cinematic reference landing page before the main investigation workflow works. If the competition demo focuses on the product, the dashboard and investigation page are the priority.

### Completion criteria

- [ ] Important information is easy to scan.
- [ ] AI and human outcomes are visually distinct.
- [ ] Status is not communicated through color alone.
- [ ] Error messages explain what happened and what to do next.
- [ ] The interface remains usable without animation.

---

## Phase 6 — Testing and Reliability

**Priority:** P0

### Backend tests

Test:
- Health endpoint.
- Alert listing and filtering.
- Valid and invalid alert IDs.
- Assessment creation and persistence.
- Invalid model response handling.
- Missing API credentials.
- Decision validation.
- Assessment-to-alert relationship validation.
- Audit event creation.
- History ordering.
- Repeated decisions.

### Frontend checks

Test:
- Dashboard loading.
- Empty alert list.
- Search and filters.
- Investigation page navigation.
- AI analysis success.
- AI analysis failure.
- Decision submission.
- History refresh.
- Narrow viewport usability.

### End-to-end scenarios

**Scenario A — Likely harmless alert**

- Open the alert.
- Run an assessment.
- Review the evidence.
- Record the analyst's decision.
- Verify the decision in history.

**Scenario B — Suspicious alert**

- Open the alert.
- Run an assessment.
- Inspect supporting indicators.
- Review recommended investigation steps.
- Record the analyst's decision.

**Scenario C — Insufficient evidence**

- Open the alert.
- Run an assessment.
- Confirm the model identifies missing information.
- Confirm the recommendation remains uncertain.
- Record `needs_further_review`.

### Completion criteria

- [ ] All core endpoints pass tests.
- [ ] Database relationships are valid.
- [ ] Errors do not corrupt saved data.
- [ ] All three scenarios work from start to finish.
- [ ] The app can be restarted without losing records.

---

## Phase 7 — Demo Preparation

**Priority:** P0

### Tasks

1. Prepare three synthetic alerts.
2. Verify model credentials and model availability.
3. Verify the full application flow on the demo machine.
4. Prepare a fallback plan for model API failures.
5. Remove debugging output and visible secrets.
6. Prepare a short README with setup instructions.
7. Record a backup demo video if permitted.
8. Confirm all competition-specific requirements.

### Suggested three-minute demo

| Time | Demonstration |
|---|---|
| 0:00–0:30 | Show the alert dashboard and explain the problem |
| 0:30–1:15 | Open an alert and run a real AI assessment |
| 1:15–1:45 | Inspect evidence, related incidents, and missing information |
| 1:45–2:20 | Record a human decision |
| 2:20–2:45 | Show the persisted investigation history |
| 2:45–3:00 | Explain the value: evidence-backed assistance with human control |

The demo must use real application behavior. Do not label prerecorded or hardcoded model output as live inference.

---

## 5. Priority Matrix

| Feature | Priority | Implementation |
|---|---|---|
| Synthetic alerts | P0 | JSON seed data + SQLite |
| Alert dashboard | P0 | React + FastAPI |
| Alert details | P0 | Database-backed page |
| Real Nebius model call | P0 | Backend AI client |
| Structured assessment | P0 | Pydantic validation |
| Assessment persistence | P0 | SQLite |
| Basic evidence | P0 | Alert data and evidence service |
| Human review | P0 | Decision API + database |
| Audit history | P0 | Audit events + timeline |
| Error and loading states | P0 | Frontend and backend |
| Similar incident retrieval | P1 | Start with simple matching |
| ChromaDB | P1 | Add if time permits |
| Tavily search | P1 | Optional public intelligence |
| Downloadable investigation report | P2 | Add after core flow |
| Authentication and team roles | P2 | Beyond the initial demo |
| Automated response actions | Out of scope | Not part of the MVP |

---

## 6. Suggested Time Allocation

Use this as a planning guide rather than a fixed estimate.

| Workstream | Approximate share |
|---|---:|
| Setup and database | 10% |
| Dashboard and alert details | 20% |
| AI integration and validation | 25% |
| Evidence and retrieval | 10% |
| Human review and audit history | 15% |
| Testing and UX polish | 15% |
| Demo preparation | 5% |

If time is limited, remove optional features before cutting tests, decision persistence, or the real model integration.

---

## 7. Development Rules

1. Build one complete vertical slice before expanding functionality.
2. Keep API keys and model calls in the backend.
3. Validate all model responses before saving them.
4. Never invent evidence or hide uncertainty.
5. Keep the original alert, AI assessment, and human decision separate.
6. Use database migrations when the schema changes.
7. Commit working milestones to Git.
8. Test the actual API rather than relying exclusively on mocked frontend responses.
9. Avoid adding tools or services unless they improve the working demo.
10. Document any incomplete or unverified integration honestly.

---

## 8. Definition of Done

ThreatIQ's MVP is complete when an analyst can:

- [ ] Open the dashboard and browse synthetic alerts.
- [ ] Open an individual alert.
- [ ] Request an assessment from a real eligible model through Nebius Token Factory.
- [ ] Read the assessment and inspect its supporting evidence.
- [ ] Understand what information is missing.
- [ ] Submit a human decision with an optional note.
- [ ] Reopen the alert and see the saved assessment and decision.
- [ ] View the investigation and audit history.
- [ ] Use the system without exposing API keys.
- [ ] Recover gracefully from a model or network failure.

**Final implementation principle:** Build the smallest complete investigation system first. Add advanced retrieval, external threat intelligence, and visual polish only after the real AI investigation, human review, persistence, and history work reliably end to end.
