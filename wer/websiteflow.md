# ThreatIQ — Website Flow

**File:** `WebsiteFlow.md`  
**Version:** 1.0  
**Product:** ThreatIQ — AI-Powered Cybersecurity Investigation Assistant  
**Purpose:** Define the website's navigation, page structure, user journeys, and interaction behavior for the hackathon MVP.

---

## 1. Website Overview

ThreatIQ is a cybersecurity investigation dashboard that helps analysts review security alerts, examine relevant evidence, understand AI-generated assessments, and record final decisions.

The website should feel like a professional security operations tool: focused, clear, fast to navigate, and built around evidence rather than decorative charts.

### Primary user journey

**Dashboard → Select Alert → Investigate → Review Evidence → Record Decision → View History**

The main workflow should be accessible in a small number of steps without unnecessary menus or configuration screens.

## 2. Website Goals

The website must allow an analyst to:

1. View and filter security alerts.
2. Open an alert and inspect its original information.
3. Run an AI-powered investigation.
4. Examine supporting evidence and related historical incidents.
5. Review external sources when available.
6. Understand missing information and uncertainty.
7. Record a human decision and reviewer note.
8. View the history of an investigation.

The interface must distinguish clearly between facts from source data, AI-generated interpretations, and decisions made by a human reviewer.

## 3. Sitemap

```text
ThreatIQ
│
├── Dashboard                 /
│   ├── Alert Overview
│   ├── Alert Filters
│   └── Alert List
│
├── Investigation             /investigations/:alertId
│   ├── Alert Details
│   ├── AI Assessment
│   ├── Supporting Evidence
│   ├── Related Incidents
│   ├── External Sources
│   ├── Recommended Steps
│   └── Human Review
│
├── Investigation History     /investigations/:alertId/history
│   ├── Previous Assessments
│   ├── Human Decisions
│   └── Audit Events
│
└── Not Found                 *
```

For the MVP, avoid separate pages for settings, user management, analytics, and integrations. They add implementation work without improving the primary demonstration.

## 4. Global Layout

### 4.1 Application shell

The main application uses a fixed navigation sidebar on desktop and a collapsible navigation menu on smaller screens.

**Sidebar**
- ThreatIQ logo and name.
- Dashboard.
- Investigations.
- A small environment label such as `DEMO ENVIRONMENT`.

**Top bar**
- Current page title.
- Search or alert lookup, if implemented.
- Data environment indicator.
- Optional profile placeholder if it does not imply authentication that has not been implemented.

**Main content**
- Page-specific content.
- Clear page headings.
- Consistent spacing and typography.
- Visible loading and error states.

### 4.2 Visual direction

Use a restrained cybersecurity-inspired interface.

- Dark navy or charcoal navigation.
- Light neutral content backgrounds, or a consistent dark theme.
- One accent color for primary actions.
- Red, amber, and green only where their meaning is clear.
- Monospaced text for technical identifiers and timestamps where useful.
- Clear severity labels that do not rely on color alone.
- Minimal decorative gradients and charts.

The design should prioritize readability and credibility over visual effects.

## 5. Page 1 — Dashboard

**Route:** `/`

**Purpose:** Give the analyst a quick overview of the available alerts and help them choose what to investigate next.

### 5.1 Page structure

#### A. Header

Display:

**Title:** Security Overview

**Subtitle:** Review alerts, investigate suspicious activity, and track decisions.

Primary action: none required. Alert selection is the main action.

#### B. Summary cards

Display four compact cards:

1. Total Alerts
2. Unresolved Alerts
3. High/Critical Alerts
4. Awaiting Review

Calculate these values from the actual dataset returned by the backend.

Do not hardcode counts or present synthetic metrics as real organizational statistics.

#### C. Filter bar

Provide:
- Search by alert title or identifier.
- Severity filter.
- Status filter.
- Clear filters action.

Suggested severity values:
- All severities
- Critical
- High
- Medium
- Low

Suggested status values:
- All statuses
- New
- Under Review
- Reviewed

#### D. Alert table

Columns:

| Column | Description |
|---|---|
| Alert | Title and alert ID |
| Severity | Severity label |
| Source | Origin of the event |
| Affected Entity | Account, device, or system |
| Time | When the event occurred |
| Status | Current review status |
| Action | Open investigation |

Each row should be clickable or include a clear `Investigate` action.

### 5.2 User interactions

- Selecting an alert opens `/investigations/:alertId`.
- Changing a filter updates the displayed rows.
- Searching filters alerts by title or ID.
- Clearing filters restores the full list.
- A refresh or return to the dashboard should preserve saved decisions.

### 5.3 Dashboard states

**Loading:** Show table skeletons or a compact loading indicator.

**Success:** Display the alert list and calculated summary cards.

**Empty search result:** Show “No alerts match your filters” and a clear-filters action.

**No alerts:** Show an informative empty state.

**API failure:** Show a retry action and a clear error message.

### 5.4 Acceptance criteria

- The dashboard loads from the backend API.
- Filters work together correctly.
- Summary counts match the returned data.
- Every listed alert links to its investigation.
- Errors do not produce fake successful data.

## 6. Page 2 — Investigation

**Route:** `/investigations/:alertId`

**Purpose:** Provide a complete view of one security alert and its AI-assisted investigation.

This is the most important page in ThreatIQ and should receive the most design and implementation attention.

### 6.1 Page header

Display:
- Breadcrumb: `Dashboard / Investigation`
- Alert title.
- Alert ID.
- Severity.
- Current review status.
- Timestamp.

Actions:
- `Analyze Alert` when no assessment exists.
- `Reanalyze` when a previous assessment exists.
- `View History` to open the investigation history page.

Reanalysis should create a new assessment rather than silently overwrite the previous one.

### 6.2 Alert details panel

Display the original alert data:

- Description.
- Source.
- Affected entity.
- Event time.
- Relevant event metadata.

The original alert must remain separate from the AI assessment.

### 6.3 AI assessment panel

This panel displays the output generated by the configured model.

Required fields:
- Summary.
- Suggested classification.
- Supporting evidence.
- Missing or conflicting information.
- Recommended next steps.

Suggested classification labels:
- Likely True Positive
- Likely False Positive
- Needs Review

Use a visible label such as **AI Recommendation — Not Yet Verified**.

The classification must never appear as a confirmed human decision until the analyst records one.

### 6.4 Supporting evidence section

Show evidence as separate cards.

Each card should contain:
- Source type: original alert, historical incident, or external source.
- Source identifier.
- Relevant evidence.
- Explanation of its relevance.

When possible, allow the analyst to open the related historical incident or external source.

Do not display a citation as verified unless it points to an actual retrieved record or source.

If no supporting evidence is found, display:

“No relevant supporting evidence was found. Additional investigation is required.”

### 6.5 Related historical incidents

Display a list of relevant past incidents.

Each item should include:
- Incident identifier.
- Short description.
- Recorded historical outcome.
- Relevant details.

If there are no matches, display an empty state instead of inventing related cases.

A similar incident is a reference, not proof that the current alert has the same cause.

### 6.6 External threat intelligence

This section is displayed when the optional external search integration is enabled.

Each result should show:
- Source title.
- Brief relevant excerpt.
- Source URL.
- Publication date, when available.

If the search fails, show:

“External threat intelligence is currently unavailable. You can continue with the available alert and historical evidence.”

Do not block the rest of the investigation.

### 6.7 Recommended next steps

Display a short, ordered list of investigation suggestions.

Examples:
- Review recent authentication activity.
- Check whether the affected account recently changed permissions.
- Verify the event against the organization's approved activity.
- Collect additional logs before making a final decision.

Recommendations must be safe and relevant to the available evidence.

The MVP should not execute these actions automatically.

### 6.8 Investigation page states

**Before analysis**

Display the alert information and a primary `Analyze Alert` button.

**Analysis in progress**

Display:
- Loading indicator.
- “Collecting relevant evidence…”
- “Generating investigation assessment…”

Only show progress stages that correspond to real backend activity. Do not simulate completion.

**Analysis complete**

Display the validated assessment and available evidence.

**Analysis failed**

Display a clear error message and `Retry Analysis` action. Preserve the original alert and any previously saved assessment.

**Insufficient evidence**

Display `Needs Review`, explain what information is missing, and suggest appropriate follow-up checks.

### 6.9 Acceptance criteria

- The page loads the correct alert by identifier.
- The original alert and AI assessment are visually distinct.
- Assessment content comes from a validated backend response.
- Evidence references correspond to available source records.
- Failed analysis does not erase previous results.
- Reanalysis preserves the history of prior assessments.

## 7. Page 3 — Human Review

**Location:** A section on the investigation page.

**Purpose:** Let the analyst make and record the final decision.

### 7.1 Review panel

Display:
- AI recommendation.
- Optional reviewer note field.
- Three decision actions.

Actions:
1. `Mark True Positive`
2. `Mark False Positive`
3. `Needs Further Review`

The interface should make clear that these actions record a review outcome. They must not trigger automatic account blocking, alert deletion, or other destructive security actions.

### 7.2 Reviewer notes

Provide an optional text area with a short placeholder:

“Explain the evidence or reasoning behind your decision…”

Validate the input length and handle empty notes appropriately.

### 7.3 Confirmation behavior

After selecting a decision:

1. Validate the decision.
2. Submit it to the backend.
3. Disable repeated submissions while the request is in progress.
4. Show a success message after the backend confirms persistence.
5. Refresh the alert status and history.

If saving fails, retain the user's note and selected decision so they can retry.

### 7.4 Displaying the saved decision

After a successful save, show a review summary:

- Final human decision.
- Reviewer note, if provided.
- Decision timestamp.
- Assessment that was reviewed.

Use separate labels for `AI Recommendation` and `Human Decision`.

The human decision may differ from the AI recommendation.

### 7.5 Acceptance criteria

- A reviewer can record any supported decision.
- The decision persists after refresh.
- The selected assessment is associated with the decision.
- The audit history records the action.
- The UI does not display success before persistence is confirmed.

## 8. Page 4 — Investigation History

**Route:** `/investigations/:alertId/history`

**Purpose:** Show how the investigation developed over time.

### 8.1 Page structure

Header:
- Alert title.
- Alert ID.
- Link back to the investigation.

History timeline:
- Investigation started.
- Assessment generated.
- Assessment regenerated, if applicable.
- Human decision recorded.
- Reviewer note added or updated, if supported.
- Status changed.

Each event should display:
- Event type.
- Timestamp.
- Relevant details.
- Assessment or decision identifier where applicable.

### 8.2 Previous assessments

When multiple assessments exist, display them in chronological order.

For each assessment, show:
- Summary.
- Suggested classification.
- Model identifier.
- Creation timestamp.

The user should be able to distinguish an earlier AI recommendation from the latest recommendation and the final human decision.

### 8.3 Empty state

If no history exists, display:

“No investigation history is available yet. Start an analysis to begin recording events.”

### 8.4 Acceptance criteria

- History is fetched from the backend.
- Events appear in a consistent order.
- Previous assessments remain available.
- The displayed final decision matches the persisted record.

## 9. Navigation and Routing

Use React Router or the routing system already available in the chosen frontend setup.

| Route | Page | Access |
|---|---|---|
| `/` | Dashboard | Public demo |
| `/investigations/:alertId` | Investigation | Public demo |
| `/investigations/:alertId/history` | Investigation History | Public demo |
| `*` | Not Found | Public demo |

Authentication is not required for the synthetic-data MVP unless the competition deployment or team requirements make it necessary.

Do not imply that the public demo is a secure production security operations system.

### Navigation rules

- The ThreatIQ logo returns to the dashboard.
- Breadcrumbs return to the appropriate parent page.
- Refreshing a valid investigation URL loads the same alert.
- Invalid identifiers display a not-found state.
- Browser back and forward navigation work as expected.

## 10. Frontend-to-Backend Interaction Flow

### Dashboard

```text
Open Dashboard
      |
      v
GET /api/v1/alerts
      |
      v
Render Summary + Alert Table
      |
      v
Select Alert
      |
      v
Navigate to Investigation
```

### Investigation

```text
Open Investigation
      |
      v
GET /api/v1/alerts/{alert_id}
      |
      v
Display Original Alert
      |
      v
Has Saved Assessment?
      |
   Yes|       No
      |        |
      v        v
Display     Analyze Alert
Saved           |
Assessment      v
          POST /api/v1/alerts/{alert_id}/analyze
                  |
                  v
          Display Validated Assessment
```

### Human review

```text
Select Decision
      |
      v
Enter Optional Note
      |
      v
Submit Decision
      |
      v
POST /api/v1/alerts/{alert_id}/decisions
      |
      v
Backend Saves Decision + Audit Event
      |
      v
Display Confirmed Human Decision
```

### History

```text
Open View History
      |
      v
GET /api/v1/alerts/{alert_id}/history
      |
      v
Render Assessments + Decisions + Events
```

## 11. Component Responsibilities

| Component | Responsibility |
|---|---|
| `AlertTable` | Display alerts and open investigations |
| `SeverityBadge` | Display consistent severity labels |
| `StatusBadge` | Display review status |
| `AlertDetails` | Display original alert information |
| `AssessmentPanel` | Display the AI recommendation |
| `EvidenceCard` | Display evidence and source references |
| `RelatedIncidents` | Display retrieved historical incidents |
| `ExternalSources` | Display public source links |
| `RecommendedSteps` | Display suggested investigation actions |
| `ReviewForm` | Capture human decisions and notes |
| `HistoryTimeline` | Display investigation events |
| `LoadingState` | Show in-progress feedback |
| `ErrorState` | Show recoverable failures |
| `EmptyState` | Explain when no results exist |

Keep components focused on displaying information and handling user interactions. API requests and complex data processing should live in a shared API service or suitable application hooks.

## 12. Frontend Data Handling

Create a central API client in `frontend/src/services/api.ts`.

It should:
- Use a configurable backend base URL.
- Set appropriate request headers.
- Parse JSON responses.
- Handle HTTP errors consistently.
- Apply request timeouts where appropriate.
- Avoid logging secrets or sensitive data.

Define TypeScript types for:
- `Alert`
- `Assessment`
- `SupportingEvidence`
- `RelatedIncident`
- `ReviewDecision`
- `AuditEvent`
- `ApiError`

Do not duplicate the same API request logic across multiple components.

After a successful review decision:
- Refresh the alert data.
- Refresh any displayed review summary.
- Refresh the investigation history when necessary.

Avoid optimistic updates that claim a decision was saved before the backend confirms it.

## 13. Responsive Design

### Desktop

- Sidebar navigation.
- Wide alert table.
- Two-column investigation layout where useful.
- Evidence and assessment panels displayed side by side when space allows.

### Tablet

- Narrower navigation.
- Responsive table or condensed alert rows.
- Stacked investigation panels when necessary.

### Mobile

- Collapsible navigation.
- Single-column investigation layout.
- Horizontally scrollable or card-based alert listings.
- Full-width review actions.
- Readable evidence cards without requiring horizontal page scrolling.

The MVP should be fully usable at typical laptop resolutions and remain functional on smaller screens.

## 14. Accessibility and Usability

- Use semantic headings and buttons.
- Give form fields visible labels.
- Provide keyboard-accessible navigation.
- Show focus states.
- Do not rely only on color to communicate severity.
- Use readable text sizes and sufficient contrast.
- Announce important status and error messages accessibly.
- Prevent accidental duplicate decision submissions.
- Use plain English for AI explanations.

## 15. Error and Recovery Behavior

| Situation | Expected behavior |
|---|---|
| Dashboard API fails | Show retry action |
| Alert does not exist | Show not-found page |
| Model request fails | Preserve alert and prior assessment |
| Model output is invalid | Reject output and show an error |
| No historical matches | Show an informative empty state |
| External search fails | Continue without external results |
| Decision save fails | Preserve the selected decision and note for retry |
| History request fails | Show retry action without hiding the investigation |
| User refreshes page | Reload persisted server data |
| Unknown route | Show a clear not-found page |

Saved demo results may be used as a fallback only when clearly labelled as saved results rather than a newly completed live analysis.

## 16. Three-Minute Demo Journey

The website must support a smooth demonstration without navigating through unnecessary pages.

### 0:00–0:30 — Dashboard

- Open ThreatIQ.
- Show the alert list and summary cards.
- Select a high-severity synthetic alert.

### 0:30–1:20 — AI investigation

- Open the investigation page.
- Run the analysis.
- Show the assessment and related historical incidents.
- Highlight the supporting evidence and missing information.

### 1:20–2:10 — Human decision

- Review the recommendation.
- Add a short note.
- Record the final human decision.
- Show the saved status.

### 2:10–2:40 — History

- Open investigation history.
- Show the assessment and decision events.

### 2:40–3:00 — Product value

Explain that ThreatIQ connects alerts to evidence, presents AI-generated recommendations transparently, and keeps final security decisions with the human analyst.

Use actual live results when available. Clearly label synthetic data and any saved fallback output.

## 17. MVP Build Priority

### P0 — Must build

- [ ] Dashboard and alert table.
- [ ] Alert detail page.
- [ ] Real Nebius/NVIDIA inference integration.
- [ ] Structured assessment display.
- [ ] Evidence display.
- [ ] Human review form.
- [ ] Decision persistence.
- [ ] Basic investigation history.
- [ ] Loading, empty, and error states.

### P1 — Build if time permits

- [ ] ChromaDB historical retrieval.
- [ ] Tavily external search.
- [ ] Assessment comparison.
- [ ] Search and advanced filters.
- [ ] Downloadable investigation report.
- [ ] Additional visual polish.

### P2 — Future enhancements

- [ ] Authentication and role-based access control.
- [ ] Real security platform integrations.
- [ ] Team assignment.
- [ ] Advanced analytics.
- [ ] Automated response workflows.
- [ ] Production-grade audit integrity.

## 18. Final Website Acceptance Checklist

The website is demo-ready when:

- [ ] The dashboard displays actual application data.
- [ ] Filters and navigation work.
- [ ] An alert opens the correct investigation.
- [ ] The AI assessment comes from a real, validated backend response.
- [ ] Supporting evidence is distinguishable from AI interpretation.
- [ ] Empty and failed retrieval states are handled.
- [ ] A human can record a decision and note.
- [ ] The saved decision persists after refresh.
- [ ] History shows the assessment and decision events.
- [ ] The website does not expose API credentials.
- [ ] The three-minute demo can be completed without broken routes or misleading states.

---

## Final UX Principle

**ThreatIQ should make every investigation understandable in seconds.**

The analyst should always be able to answer four questions:

1. What happened?
2. What evidence supports the assessment?
3. What information is still missing?
4. What decision has the human reviewer made?

Every page, component, and interaction should support one or more of these questions.
