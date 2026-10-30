# ThreatIQ
## Product Requirements Document (PRD)

**Product:** ThreatIQ — AI-Powered Cybersecurity Investigation Assistant  
**Competition:** Nebius × NVIDIA Global AI Hackathon  
**Product Type:** Web Application  
**Document Version:** 1.0  
**Status:** MVP Specification  
**Primary Goal:** Build a working, evidence-backed cybersecurity investigation assistant that helps analysts understand, prioritize, and review security alerts.

---

## 1. Executive Summary

ThreatIQ is an AI-powered cybersecurity investigation assistant designed to help security analysts investigate suspicious system activity, understand security alerts, and make better-informed decisions.

Security teams often receive large numbers of alerts from authentication systems, applications, networks, and other security tools. Investigating each alert manually requires time, technical knowledge, and access to relevant historical information. Some alerts are harmless, while others may indicate genuine security threats.

ThreatIQ brings alert information, relevant historical incidents, public threat intelligence, and AI-generated explanations into one interface.

The system analyzes an alert, retrieves supporting information, generates an evidence-backed assessment, and recommends appropriate investigation steps. A human analyst remains responsible for the final decision.

The MVP will use synthetic security data, a supported NVIDIA open model accessed through Nebius Token Factory, and a simple web interface. External threat intelligence search and historical incident retrieval will improve the quality and traceability of the analysis.

**Core principle: ThreatIQ assists security decisions; it does not replace security analysts or automatically declare systems safe.**

## 2. Problem Statement

Security analysts face three major challenges:

1. **Alert overload:** Large numbers of alerts make it difficult to identify which incidents deserve immediate attention.
2. **Scattered evidence:** Relevant information may be distributed across alert records, historical incidents, identity logs, and public security advisories.
3. **Time-consuming investigations:** Analysts must manually connect events, interpret evidence, document findings, and decide what to investigate next.

Traditional dashboards help organize alerts but do not necessarily explain the relationship between an alert and the available evidence.

ThreatIQ addresses this problem by providing a single investigation workflow that combines relevant evidence, AI-generated explanations, suggested next steps, and human review.

## 3. Product Vision

Make cybersecurity investigations faster, clearer, and more explainable by turning individual security alerts into structured investigations supported by evidence.

### Product objectives

- Reduce the manual effort required to understand an individual alert.
- Retrieve relevant information from previously investigated incidents.
- Provide clear explanations supported by identifiable evidence.
- Help analysts prioritize incidents without treating AI output as certainty.
- Record human decisions and investigation history.
- Demonstrate a reliable end-to-end AI application using the hackathon's required technologies.

### Success criteria

The MVP should allow a judge or analyst to:

- Open a dashboard containing sample security alerts.
- Select an alert and view a structured AI assessment.
- Inspect the evidence behind that assessment.
- Review related historical incidents and, when enabled, external sources.
- Record a final human decision.
- View the resulting investigation history.

## 4. Target Users

### Primary user: Security analyst

A security analyst responsible for reviewing alerts, investigating suspicious activity, and deciding whether further action is necessary.

**Needs:**
- Quickly understand an alert.
- Find related incidents and relevant evidence.
- Understand why an alert may be suspicious.
- Identify missing information.
- Document investigation decisions.

### Secondary user: Security team lead

A team lead who needs visibility into unresolved alerts, investigation status, review outcomes, and analyst decisions.

**Needs:**
- Identify high-priority unresolved cases.
- Track case progress.
- Review final decisions and investigation notes.

The MVP focuses on the analyst workflow. Advanced team management, enterprise access controls, and organizational reporting are outside the initial scope.

## 5. Product Scope

### 5.1 In scope for the MVP

1. Security alert dashboard.
2. Alert details and severity indicators.
3. AI-generated incident summaries.
4. Retrieval of similar historical incidents.
5. Evidence-backed investigation explanations.
6. Optional public threat intelligence search through Tavily.
7. Suggested next investigation steps.
8. Human review and decision recording.
9. Investigation history and basic audit trail.
10. Synthetic sample data and predefined demonstration scenarios.

### 5.2 Out of scope

- Automatic blocking of users, IP addresses, or devices.
- Automatic closure of potentially malicious incidents.
- Production integrations with enterprise security platforms.
- Training a custom cybersecurity foundation model.
- Real-time monitoring of an organization's entire network.
- Autonomous incident response agents.
- Malware execution or active penetration testing.
- Claims of production-grade threat detection accuracy.
- Complex multi-agent orchestration.

These exclusions keep the project achievable, testable, and safe within a hackathon timeline.

## 6. Core User Workflow

The main workflow is:

**Alert → Evidence Collection → AI Assessment → Human Review → Recorded Decision**

### Step 1: View security alerts

The analyst opens the dashboard and sees a list of alerts.

Each alert displays:
- Alert ID
- Alert title
- Source or affected entity
- Timestamp
- Severity
- Review status

The dashboard supports filtering by severity and review status.

### Step 2: Open an alert

The analyst selects an alert to view its original details, including the event type, available timestamps, affected account or system, source information, and relevant metadata.

The original alert information must remain accessible so the AI summary does not replace the underlying evidence.

### Step 3: Collect relevant evidence

ThreatIQ retrieves:
- The original alert fields.
- Similar historical incidents from the local incident collection.
- Relevant public security information, when external search is enabled.

Each retrieved item should retain its source, identifier, or URL wherever available.

If evidence cannot be found, the system must say so instead of inventing supporting information.

### Step 4: Generate the AI assessment

The application sends the alert and retrieved evidence to an NVIDIA open model through Nebius Token Factory.

The model returns a structured assessment containing:

- A concise incident summary.
- A suggested classification.
- Supporting evidence.
- Conflicting or missing information.
- Recommended next investigation steps.
- References to the evidence used.

The assessment is advisory, not a confirmed security verdict.

### Step 5: Review the recommendation

The analyst can:
- Mark the case as a true positive.
- Mark the case as a false positive.
- Keep the case open for further review.
- Add investigation notes.

The analyst must be able to disagree with the AI.

### Step 6: Record the outcome

ThreatIQ saves the human decision, reviewer notes, timestamp, and relevant assessment information.

The updated case status appears in the dashboard and investigation history.

## 7. Functional Requirements

### FR-01: Security alert dashboard

**Priority:** P0 — Essential

The dashboard must:
- Display a predefined collection of security alerts.
- Show alert title, severity, timestamp, and status.
- Support filtering by severity and status.
- Allow the analyst to open an alert.
- Clearly distinguish unresolved cases from reviewed cases.

**Acceptance criteria:** The analyst can select any sample alert and navigate to its detail view without a broken route.

### FR-02: Alert detail view

**Priority:** P0 — Essential

The detail view must:
- Display the original alert data.
- Show the current investigation status.
- Provide an action to start or view an analysis.
- Display the most recent assessment when one exists.

**Acceptance criteria:** The original alert remains available alongside the generated assessment.

### FR-03: AI-powered investigation

**Priority:** P0 — Essential

ThreatIQ must call a supported NVIDIA open model through Nebius Token Factory.

The model must produce a structured response containing:
- Summary
- Suggested classification
- Supporting evidence
- Missing or conflicting evidence
- Recommended next steps

Suggested classifications:
- `likely_true_positive`
- `likely_false_positive`
- `needs_review`

These classifications are recommendations, not verified outcomes.

**Acceptance criteria:** The application successfully makes a runtime model call and returns a valid assessment for the prepared demonstration alerts.

### FR-04: Historical incident retrieval

**Priority:** P0 — Essential

ThreatIQ must search a collection of previously resolved synthetic incidents and return relevant matches.

ChromaDB may be used to retrieve semantically similar incidents.

Each result should contain:
- Incident identifier
- Short description
- Recorded outcome
- Relevant details

**Acceptance criteria:** At least one relevant historical incident can be displayed when a suitable match exists. If none exists, the interface must clearly indicate that no relevant match was found.

### FR-05: Evidence display

**Priority:** P0 — Essential

The assessment view must distinguish between:
- Facts taken from the original alert.
- Information retrieved from historical incidents.
- Information found in external sources.
- AI-generated interpretations and recommendations.

The interface must show source references where available.

**Acceptance criteria:** A reviewer can identify where the supporting information came from without relying solely on the model's explanation.

### FR-06: External threat intelligence

**Priority:** P1 — Recommended

When enabled, Tavily can search public security advisories, vulnerability information, and other relevant security resources.

The application must:
- Search using a relevant query derived from the alert.
- Display the source title and URL.
- Associate retrieved information with the relevant investigation.
- Avoid presenting search results as proof that an incident occurred.

If external search fails, the application must continue with the available local evidence.

**Acceptance criteria:** A successful search displays clickable source links. Search failure does not prevent the analyst from reviewing the incident.

### FR-07: Human decision recording

**Priority:** P0 — Essential

The analyst must be able to record:
- True positive
- False positive
- Needs further review

The analyst may also add a note explaining the decision.

The system must save the final decision separately from the AI recommendation.

**Acceptance criteria:** Refreshing the page does not erase a saved decision.

### FR-08: Investigation history

**Priority:** P0 — Essential

The application must record significant actions, including:
- Analysis requested.
- Assessment generated.
- Human decision recorded.
- Review note added.
- Case status changed.

Each event should contain a timestamp, case identifier, action, and relevant details.

**Acceptance criteria:** The analyst can inspect the recorded sequence of events for a reviewed case.

### FR-09: Error handling

**Priority:** P0 — Essential

The application must handle:
- Model API failures.
- Invalid model responses.
- Empty retrieval results.
- External search failures.
- Missing alert fields.
- Failed decision saves.

The interface must display understandable error messages and allow safe retries where appropriate.

The application must never silently replace a failed analysis with a fabricated result.

### FR-10: Demonstration dataset

**Priority:** P0 — Essential

Provide 10–20 synthetic security alerts and 5–10 historical incidents.

Prepare three demonstration cases:
1. An alert with evidence suggesting a harmless event.
2. An alert with multiple indicators of suspicious activity.
3. An alert with insufficient or conflicting evidence.

Expected outcomes should be defined before testing. The dataset must be clearly identified as synthetic.

## 8. Non-Functional Requirements

### Performance
- Keep the dashboard responsive during normal demo use.
- Display a loading state while the model or search service is working.
- Avoid unnecessary model calls by allowing previously generated assessments to be viewed.
- Set reasonable request timeouts.

### Reliability
- Provide a backup demonstration dataset and saved assessment results.
- Ensure one failed external service does not crash the entire application.
- Validate model responses before displaying them.

### Security
- Keep API keys on the backend.
- Store secrets in environment variables or an appropriate secret-management system.
- Never expose credentials in browser code, source control, or logs.
- Use synthetic data for the hackathon demonstration.
- Validate user input and retrieved content.
- Treat external documents and alert text as untrusted data.

### Explainability
- Display supporting evidence separately from AI interpretation.
- Preserve the original alert.
- Show missing evidence and uncertainty.
- Avoid presenting a model-generated confidence score as a calibrated probability unless it has been properly evaluated.

### Usability
- Use clear labels and short explanations.
- Keep the main investigation workflow on a small number of screens.
- Make unresolved cases and required human actions easy to identify.

## 9. Technology Stack

### Frontend
- React with TypeScript.
- Tailwind CSS for styling.
- A charting library only if a meaningful visualization is needed.

Responsibilities:
- Alert dashboard.
- Investigation detail page.
- Evidence cards.
- Review controls.
- Investigation history.

### Backend
- Python.
- FastAPI.

Responsibilities:
- Alert retrieval.
- Investigation orchestration.
- Model API calls.
- Historical incident retrieval.
- External threat intelligence lookup.
- Response validation.
- Decision persistence and audit events.

### AI inference
- Nebius Token Factory.
- A supported NVIDIA open model, such as an available Nemotron model.

Responsibilities:
- Summarize alert information.
- Interpret supplied evidence.
- Produce structured assessments.
- Suggest additional investigation steps.

The exact model should be selected after checking current availability, latency, cost, and hackathon eligibility.

### Historical retrieval
- ChromaDB.

Responsibilities:
- Store historical incident descriptions and associated metadata.
- Retrieve relevant prior cases.
- Return source identifiers for the assessment.

For the initial demo, a small local collection is sufficient.

### External information
- Tavily API, if implemented.

Responsibilities:
- Search relevant public threat intelligence.
- Return source links and useful excerpts.

### Persistence
- SQLite for a simple local MVP, or PostgreSQL if the team already has a working database setup.

Store alerts, assessments, human decisions, and audit events.

### Deployment
- Deploy the frontend and backend using services the team can configure reliably.
- Ensure the deployed application makes its actual model inference call through the required Nebius service.

**Important competition requirement:** Verify the latest official rules and model eligibility. The implementation must satisfy the Nebius runtime requirement and the required NVIDIA open-model usage; merely mentioning these technologies in the documentation is insufficient.

## 10. System Architecture

The system should follow a simple, testable pipeline.

1. The frontend requests an alert from the backend.
2. The backend validates and loads the alert.
3. The retrieval component searches historical incidents.
4. The optional external search component retrieves public information.
5. The backend builds a structured evidence package.
6. The model generates an assessment through Nebius Token Factory.
7. The backend validates the response and associates claims with available evidence.
8. The frontend displays the assessment and source information.
9. The analyst records a decision.
10. The backend persists the decision and audit event.

### Architecture principles

- Use one backend orchestration flow.
- Keep evidence retrieval separate from AI interpretation.
- Keep final decision handling deterministic.
- Avoid adding a multi-agent architecture.
- Make external integrations optional rather than mandatory for every request.
- Ensure that the application remains useful when no external information is available.

## 11. Data Model

### SecurityAlert

| Field | Type | Purpose |
|---|---|---|
| id | String | Unique alert identifier |
| title | String | Short alert title |
| description | String | Original alert description |
| severity | Enum | Low, medium, high, critical |
| source | String | Origin of the alert |
| affected_entity | String | Account, device, or system |
| occurred_at | Timestamp | Time of the event |
| status | Enum | New, analyzing, under_review, reviewed |

### Assessment

| Field | Type | Purpose |
|---|---|---|
| id | String | Unique assessment identifier |
| alert_id | String | Associated alert |
| summary | String | AI-generated summary |
| suggested_classification | Enum | Likely true positive, likely false positive, needs review |
| supporting_evidence | Array | Evidence references and explanations |
| missing_information | Array | Missing or conflicting information |
| recommended_steps | Array | Suggested investigation actions |
| model_id | String | Model used |
| created_at | Timestamp | Assessment time |

### ReviewDecision

| Field | Type | Purpose |
|---|---|---|
| id | String | Unique decision identifier |
| alert_id | String | Associated alert |
| decision | Enum | True positive, false positive, needs review |
| reviewer_note | String | Optional explanation |
| reviewer_id | String | Reviewer identifier, if authentication exists |
| created_at | Timestamp | Decision time |

### AuditEvent

| Field | Type | Purpose |
|---|---|---|
| id | String | Unique event identifier |
| alert_id | String | Associated alert |
| action | String | Event type |
| details | Object | Relevant event details |
| created_at | Timestamp | Event time |

For the MVP, use a local database and synthetic reviewer identities. Do not claim enterprise-grade audit integrity or access control unless those mechanisms are implemented and tested.

## 12. API Specification

### `GET /alerts`

Returns a list of security alerts.

Supports optional filters:
- `severity`
- `status`

### `GET /alerts/{alert_id}`

Returns the original alert details and its current status.

### `POST /alerts/{alert_id}/analyze`

Runs an investigation.

Suggested response:

```json
{
  "alert_id": "ALT-001",
  "summary": "Unusual sign-in activity requires review.",
  "suggested_classification": "needs_review",
  "supporting_evidence": [],
  "missing_information": [],
  "related_incidents": [],
  "external_sources": [],
  "recommended_steps": []
}
```

The fields shown are a response contract; actual results must be populated from the application and its model output.

### `POST /alerts/{alert_id}/decision`

Records a human review decision.

Example request:

```json
{
  "decision": "needs_review",
  "reviewer_note": "Additional authentication logs are required."
}
```

### `GET /alerts/{alert_id}/history`

Returns the saved assessment and audit events for the alert.

All endpoints must validate input, return appropriate error responses, and avoid leaking secrets.

## 13. AI Output and Safety Rules

ThreatIQ must follow these rules:

1. The model may recommend a classification but must not automatically finalize the case.
2. Every displayed factual claim should be linked to available evidence when possible.
3. Missing information must be identified explicitly.
4. The model must not invent historical incidents, source links, or security events.
5. Retrieved documents must be treated as data, not instructions to the AI system.
6. Suspicious content must not be executed.
7. External search results must be treated as untrusted until evaluated.
8. A failed model request must produce a clear error or an explicitly labelled saved result, never a fabricated live result.
9. Human decisions must be stored separately from AI recommendations.
10. Potentially malicious cases must not be silently dismissed because a similar historical incident was harmless.

The MVP is a decision-support tool, not a replacement for professional incident response.

## 14. Testing and Evaluation

Evaluation must use predefined examples with known expected outcomes.

### Test dataset

Prepare 10–20 synthetic alerts covering:
- Normal authentication.
- Repeated failed login attempts.
- Unusual login locations.
- Suspicious privilege changes.
- Potential account compromise.
- Missing or conflicting event information.

Use historical incidents with documented outcomes to test retrieval.

### Functional tests

- Dashboard loads the alert list.
- Filters return the expected cases.
- Alert details match the stored source data.
- Model requests use the configured provider.
- Assessment output follows the required schema.
- Evidence references point to actual retrieved items.
- Human decisions persist after refresh.
- Audit history reflects recorded actions.
- External search failure does not break the workflow.

### Quality metrics

Measure:
- **Classification quality:** How often the suggested classification matches the labelled examples.
- **Retrieval relevance:** Whether useful historical incidents appear near the top.
- **Evidence support:** Whether the explanation is supported by the supplied records.
- **Response validity:** Whether model responses follow the expected schema.
- **Latency:** Time required to generate an assessment.
- **Human review completion:** Whether the full workflow can be completed without errors.

Report the actual test results. Do not claim an accuracy percentage, time saving, or performance improvement before measuring it.

## 15. User Interface Requirements

### Screen 1: Dashboard

Display:
- Total number of sample alerts.
- Number of unresolved alerts.
- Number of high-severity alerts.
- Alert table with severity and status.
- Search or filter controls.

These counts must be calculated from the actual application data.

### Screen 2: Investigation

Display:
- Alert summary and original details.
- Severity and current status.
- AI-generated assessment.
- Supporting evidence cards.
- Related historical incidents.
- External source links, if available.
- Missing information.
- Recommended next steps.

### Screen 3: Human Review

Display:
- The AI recommendation.
- Decision buttons.
- An optional reviewer note.
- Confirmation after saving.

### Screen 4: Investigation History

Display:
- Analysis timestamp.
- Previous assessment, where retained.
- Human decision.
- Reviewer note.
- Recorded status changes.

The visual design should be clean, professional, and information-focused. Use readable typography, clear severity indicators, consistent spacing, and accessible contrast. Avoid decorative charts that do not help analysts make decisions.

## 16. MVP Development Roadmap

### Phase 1: Core application

- Set up the frontend and FastAPI backend.
- Create the synthetic alert dataset.
- Implement the dashboard and alert detail page.
- Add the database models.

**Deliverable:** A functional alert dashboard.

### Phase 2: AI investigation

- Configure Nebius Token Factory access.
- Select and test a supported NVIDIA open model.
- Implement the structured assessment prompt.
- Validate the response format.
- Display summaries and recommendations.

**Deliverable:** An alert can be analyzed through the required AI provider.

### Phase 3: Evidence retrieval

- Add historical incident retrieval using ChromaDB.
- Display related cases and their source information.
- Add Tavily search if time and API access permit.
- Handle empty results and service failures.

**Deliverable:** An assessment that incorporates available supporting information.

### Phase 4: Human review

- Add decision buttons and reviewer notes.
- Persist decisions.
- Add investigation history.
- Test that AI recommendations and final decisions remain separate.

**Deliverable:** A complete investigation workflow.

### Phase 5: Demo readiness

- Test the three prepared scenarios.
- Fix critical failures.
- Prepare saved example outputs as a clearly labelled fallback.
- Deploy and verify the working application.
- Prepare the README, architecture diagram, and demo presentation.

**Deliverable:** A reliable, reproducible hackathon demonstration.

## 17. Demo Plan

The demonstration should take approximately three minutes.

### Scenario 1: Harmless activity

Open an alert with evidence consistent with a normal event.

Show how ThreatIQ retrieves a relevant historical case, explains the available evidence, and allows the analyst to record a false-positive decision.

### Scenario 2: Suspicious activity

Open an alert containing several indicators of suspicious behaviour.

Show the AI assessment, related incidents, supporting information, and suggested next investigation steps.

The analyst reviews the evidence and records the final decision.

### Scenario 3: Insufficient evidence

Open an alert with missing or conflicting information.

Show that ThreatIQ identifies the uncertainty and recommends further investigation instead of inventing a confident verdict.

**Closing message:** ThreatIQ does not merely summarize security alerts. It connects alerts to evidence, explains what is known and unknown, and helps analysts make traceable decisions.

## 18. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Model API failure | Timeouts, clear error states, saved demo outputs |
| Incorrect AI assessment | Human review and evidence inspection |
| Irrelevant historical matches | Small labelled dataset and retrieval testing |
| Unsupported AI claims | Evidence references and explicit missing-information fields |
| External search failure | Keep local incident retrieval independent |
| Excessive scope | Prioritize the core workflow before optional integrations |
| API key exposure | Backend-only secrets and environment configuration |
| Unverified competition compliance | Test the actual Nebius and NVIDIA model integration |

## 19. Final MVP Acceptance Criteria

The MVP is ready for submission when:

- [ ] The web application runs reliably.
- [ ] The dashboard displays the synthetic alert dataset.
- [ ] An analyst can open and inspect an alert.
- [ ] The application performs a real inference call through the required Nebius service using an eligible NVIDIA open model.
- [ ] The assessment contains a summary, suggested classification, evidence, uncertainty, and next steps.
- [ ] Relevant historical incidents can be retrieved when available.
- [ ] External sources are shown with links when the optional search integration is enabled.
- [ ] An analyst can record a final decision and note.
- [ ] The decision and history persist after refresh.
- [ ] The three prepared scenarios can be demonstrated end to end.
- [ ] Known limitations and measured test results are documented.

## 20. Future Enhancements

After the MVP is stable, possible improvements include:

- Integration with real security information and event management systems.
- More advanced incident correlation across multiple events.
- Role-based access control.
- Team assignment and collaboration.
- Better historical retrieval and ranking.
- Automated evaluation against a larger labelled dataset.
- Additional supported model comparisons.
- Carefully controlled integrations with incident-response workflows.

These enhancements should be pursued only after the initial workflow is reliable and the team has evidence that each addition improves the product.

---

## Final Product Definition

**ThreatIQ is an AI-powered cybersecurity investigation assistant that connects security alerts with historical incidents and relevant threat information, generates evidence-backed assessments using NVIDIA open models through Nebius, and keeps the final decision in human hands.**

Its core differentiator is not simply using AI to classify alerts. It is making the investigation process more understandable, evidence-based, and traceable while explicitly acknowledging uncertainty.
