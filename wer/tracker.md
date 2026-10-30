# ThreatIQ — Implementation Tracker

## 1. Project Status

**Project:** ThreatIQ — AI-Powered Cybersecurity Investigation Assistant  
**Current phase:** Implementation  
**Primary objective:** Deliver a working end-to-end cybersecurity investigation demo.

### Status definitions

- `[ ]` Not started
- `[-]` In progress
- `[x]` Completed
- `[!]` Blocked
- `[?]` Needs verification

**Rule:** Mark a task completed only after implementation and the relevant verification are finished.

---

## 2. Core MVP Tracker

### Phase 0 — Project Setup

- [ ] Create the repository structure.
- [ ] Initialize the React + TypeScript frontend.
- [ ] Initialize the FastAPI backend.
- [ ] Install and verify dependencies.
- [ ] Create `.env.example`.
- [ ] Configure environment variables.
- [ ] Verify Nebius API credentials and model availability.
- [ ] Confirm the selected NVIDIA model meets competition requirements.
- [ ] Configure SQLite.
- [ ] Implement `GET /api/v1/health`.
- [ ] Create synthetic alert data.
- [ ] Create synthetic historical-incident data.
- [ ] Add `.env`, database files, and other secrets to `.gitignore`.

**Exit criteria:** Frontend, backend, database, and synthetic data work locally.

### Phase 1 — Database and Dashboard

- [ ] Implement `SecurityAlert`.
- [ ] Implement `Assessment`.
- [ ] Implement `ReviewDecision`.
- [ ] Implement `AuditEvent`.
- [ ] Configure foreign keys and indexes.
- [ ] Create database tables or migrations.
- [ ] Seed synthetic alerts.
- [ ] Implement `GET /api/v1/alerts`.
- [ ] Implement `GET /api/v1/alerts/{alert_id}`.
- [ ] Add severity filtering.
- [ ] Add workflow-status filtering.
- [ ] Add alert search.
- [ ] Build the dashboard.
- [ ] Build the alert table.
- [ ] Add severity and status indicators.
- [ ] Connect the frontend to the backend.
- [ ] Add loading, empty, and error states.

**Exit criteria:** An analyst can browse, filter, and open database-backed alerts.

### Phase 2 — AI Investigation

- [ ] Implement the Nebius API client.
- [ ] Configure the selected model.
- [ ] Keep credentials on the backend.
- [ ] Create the system prompt.
- [ ] Define the Pydantic assessment schema.
- [ ] Implement `POST /api/v1/alerts/{alert_id}/analyze`.
- [ ] Send alert information to the model.
- [ ] Validate the model response.
- [ ] Support `likely_true_positive`.
- [ ] Support `likely_false_positive`.
- [ ] Support `needs_review`.
- [ ] Include a plain-language summary.
- [ ] Include supporting evidence references.
- [ ] Include missing information.
- [ ] Include recommended investigation steps.
- [ ] Persist successful assessments.
- [ ] Record assessment failures where possible.
- [ ] Display the assessment on the investigation page.
- [ ] Add a retry path for recoverable failures.
- [ ] Verify that saved assessments survive a restart.

**Exit criteria:** A real model produces a validated, persisted assessment that appears in the UI.

### Phase 3 — Evidence and Retrieval

- [ ] Implement the evidence service.
- [ ] Display facts from the original alert.
- [ ] Load synthetic historical incidents.
- [ ] Implement basic similar-incident matching.
- [ ] Display related incidents.
- [ ] Preserve source identifiers.
- [ ] Distinguish observed facts from AI interpretations.
- [ ] Display missing evidence or information.
- [ ] Verify that evidence references resolve correctly.
- [ ] Evaluate whether ChromaDB is necessary.
- [ ] Integrate ChromaDB if time permits.
- [ ] Evaluate whether Tavily is necessary.
- [ ] Integrate Tavily if time permits.
- [ ] Store external source URLs and retrieval timestamps.
- [ ] Handle retrieval failures gracefully.

**Exit criteria:** Analysts can inspect the evidence behind an assessment. Optional retrieval integrations are not required for the basic MVP.

### Phase 4 — Human Review

- [ ] Implement decision request validation.
- [ ] Implement `POST /api/v1/alerts/{alert_id}/decisions`.
- [ ] Support `true_positive`.
- [ ] Support `false_positive`.
- [ ] Support `needs_further_review`.
- [ ] Add an optional reviewer note.
- [ ] Associate decisions with the relevant assessment.
- [ ] Validate that the assessment belongs to the same alert.
- [ ] Persist decisions.
- [ ] Preserve earlier decisions.
- [ ] Update alert workflow status appropriately.
- [ ] Add decision success and failure feedback.
- [ ] Display the latest human decision.
- [ ] Keep the AI recommendation separate from the human decision.

**Exit criteria:** Human decisions persist and remain independent of AI recommendations.

### Phase 5 — Audit History

- [ ] Record alert creation events.
- [ ] Record assessment success events.
- [ ] Record assessment failure events.
- [ ] Record human decision events.
- [ ] Record relevant workflow-status changes.
- [ ] Implement `GET /api/v1/alerts/{alert_id}/history`.
- [ ] Build the history timeline.
- [ ] Sort events chronologically.
- [ ] Display timestamps and event types.
- [ ] Verify that prior decisions remain visible.
- [ ] Restrict ordinary application operations from modifying historical audit events.

**Exit criteria:** The analyst can inspect the alert's investigation history after refreshing or restarting the application.

### Phase 6 — UI and Design

- [ ] Apply the ThreatIQ color palette.
- [ ] Configure Space Grotesk and JetBrains Mono.
- [ ] Style the navigation.
- [ ] Style the dashboard.
- [ ] Style the investigation page.
- [ ] Style evidence sections.
- [ ] Style assessment classifications.
- [ ] Style human review controls.
- [ ] Style the audit timeline.
- [ ] Add visible keyboard focus.
- [ ] Add responsive layouts.
- [ ] Add reduced-motion support where animations exist.
- [ ] Verify text contrast.
- [ ] Remove misleading placeholder content.
- [ ] Verify that reference statistics are not presented as actual ThreatIQ metrics.

**Exit criteria:** The UI is readable, consistent, responsive, and suitable for a live demo.

### Phase 7 — Testing

- [ ] Test the health endpoint.
- [ ] Test alert listing and filtering.
- [ ] Test invalid alert IDs.
- [ ] Test assessment creation.
- [ ] Test assessment persistence.
- [ ] Test missing API credentials.
- [ ] Test model timeout handling.
- [ ] Test invalid model output.
- [ ] Test decision validation.
- [ ] Test assessment-to-alert relationships.
- [ ] Test audit event creation.
- [ ] Test history ordering.
- [ ] Test repeated analyst decisions.
- [ ] Test database restart persistence.
- [ ] Test frontend loading and empty states.
- [ ] Test model failure in the UI.
- [ ] Run an end-to-end test for all three demo scenarios.

**Exit criteria:** Core workflows work without fabricated AI output or lost review decisions.

### Phase 8 — Demo and Submission

- [ ] Prepare a likely harmless synthetic alert.
- [ ] Prepare a suspicious synthetic alert.
- [ ] Prepare an insufficient-evidence synthetic alert.
- [ ] Verify the real model call on the demo machine.
- [ ] Verify the complete workflow from dashboard to history.
- [ ] Check logs for exposed secrets.
- [ ] Prepare README setup instructions.
- [ ] Confirm required competition integrations.
- [ ] Verify deployment, if applicable.
- [ ] Prepare the three-minute demo script.
- [ ] Record a backup demo, if permitted.
- [ ] Check the final submission requirements.
- [ ] Verify that all claims match the implementation.

**Exit criteria:** The project can be demonstrated reliably from a clean start, and the submission accurately describes what works.

---

## 3. Critical End-to-End Workflow

Use this checklist as the main measure of MVP readiness.

- [ ] **Step 1:** Open the dashboard.
- [ ] **Step 2:** Select a synthetic security alert.
- [ ] **Step 3:** Open the investigation page.
- [ ] **Step 4:** Request a real AI assessment.
- [ ] **Step 5:** Review the summary and classification.
- [ ] **Step 6:** Inspect evidence and related incidents.
- [ ] **Step 7:** Review missing information and recommended steps.
- [ ] **Step 8:** Submit a human decision.
- [ ] **Step 9:** Confirm the decision was saved.
- [ ] **Step 10:** Open the history timeline.
- [ ] **Step 11:** Verify that the assessment, decision, and audit events remain available after refresh.

**MVP rule:** Do not prioritize optional integrations or elaborate animations over this complete workflow.

---

## 4. Bug and Blocker Tracker

Record issues here as they arise.

| ID | Issue | Severity | Status | Next action |
|---|---|---|---|---|
| BUG-001 | To be recorded | — | Not started | Describe reproduction steps |
| BUG-002 | To be recorded | — | Not started | Describe reproduction steps |
| BUG-003 | To be recorded | — | Not started | Describe reproduction steps |

Suggested severity levels:

- **Critical:** The demo cannot run or core data is lost.
- **High:** A core workflow is broken.
- **Medium:** A feature works incorrectly but a workaround exists.
- **Low:** Minor visual or usability issue.

Do not leave a blocker as a vague description. Record the error, reproduction steps, and the next action.

---

## 5. Decisions and Verification Log

Record decisions that affect implementation.

| Date | Decision or question | Status |
|---|---|---|
| YYYY-MM-DD | Selected Nebius model and verified API access | Pending verification |
| YYYY-MM-DD | Chose SQLite for the MVP | Planned |
| YYYY-MM-DD | Decided whether to use ChromaDB | Pending |
| YYYY-MM-DD | Decided whether to enable Tavily | Pending |
| YYYY-MM-DD | Verified competition compliance | Pending verification |

Replace the example dates with the actual dates when decisions are made. Do not mark a technical integration or competition requirement as verified without evidence.

---

## 6. Optional Features Tracker

Only begin these after the core MVP works end to end.

- [ ] ChromaDB-based historical retrieval.
- [ ] Tavily public threat-intelligence search.
- [ ] Downloadable investigation report.
- [ ] PostgreSQL deployment.
- [ ] Authentication and role-based access.
- [ ] Team assignment and collaboration.
- [ ] Advanced dashboard analytics.
- [ ] Production deployment and monitoring.

For each optional feature, record its expected demo value, estimated effort, and whether it is necessary for the competition.

---

## 7. Daily Progress Log

Add one entry per development session.

### Session template

**Date:** YYYY-MM-DD

**Planned tasks:**
- [ ] Task 1
- [ ] Task 2

**Completed:**
- 

**Tests run:**
- 

**Blockers:**
- 

**Next session:**
- 

**Current working state:**
- Frontend:
- Backend:
- Database:
- AI integration:
- End-to-end workflow:

---

## 8. Definition of Done

ThreatIQ is ready for its MVP demo when all the following are true:

- [ ] The dashboard displays real database records.
- [ ] A user can open an alert and run real model inference.
- [ ] The model output is validated before being stored.
- [ ] Evidence and uncertainty are visible.
- [ ] Human review decisions are saved independently.
- [ ] Investigation history is persisted.
- [ ] The core workflow survives a page refresh and application restart.
- [ ] Errors are handled without inventing successful results.
- [ ] API credentials remain private.
- [ ] The three demo scenarios work.
- [ ] Competition-specific requirements have been verified.

**Final rule:** Update this tracker based on actual implementation and test results. The checklist describes the intended work; it does not imply that any task has already been completed.
