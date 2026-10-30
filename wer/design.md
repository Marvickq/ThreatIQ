<!-- V2-CURRENT -->
> **V2 is current.** The sections below this block were written for V1 (single organization, SQLite MVP, unauthenticated) and are kept for history. Where they conflict with this block, this block wins.


# V2 — current design

The visual identity above (black, white, restrained red, Space Grotesk + JetBrains Mono, sharp corners) is kept. The product is now a multi-page SaaS application built with **shadcn/ui** components (Radix primitives) themed through CSS variables in `frontend/src/index.css`, **Recharts** charts, **TanStack Query** data layer, **Zod**-validated API responses and forms, **sonner** toasts, and **lucide** icons.

- **Shell:** sidebar (Dashboard, Alerts, Settings), top bar with organization switcher, role badge, notifications popover, account menu; skip-to-content link; offline banner; live-updates indicator.
- **States designed for every data view:** loading skeletons, empty (with next steps), error (with request ID and retry), **stale** (cached data kept with a "could not refresh" banner), **permission denied**, **offline**, not found; route protection; an error boundary.
- **Severity/status never rely on colour alone** (text + glyph). AI output is labelled "AI recommendation · not yet verified" and shown apart from facts, evidence and the human decision. Demo data is badged wherever it appears.
- **Accessibility:** semantic landmarks and headings, labelled form controls, visible focus, keyboard-operable menus/dialogs/tables (`aria-sort`, confirmation dialogs), `aria-live` for progress, reduced-motion respected, no horizontal page overflow at 390 px (checked on dashboard, alerts, alert detail, settings).
- **Internationalization:** locale- and timezone-aware dates and numbers; message catalog in `src/i18n/` (English only; some newer strings are not yet extracted).
- Charts have text alternatives; the landing-page video/animation spec above is **not implemented** (the app starts at sign-in).
<!-- /V2-CURRENT -->

# ThreatIQ — Website Design Specification

## 1. Design Vision

**Product:** ThreatIQ — AI-Powered Cybersecurity Investigation Assistant

**Design direction:** Dark, minimal, technical, evidence-driven.

ThreatIQ should feel like a professional Security Operations Center (SOC) investigation tool, not a marketing template or a generic AI chatbot.

The supplied reference image defines the visual language:

- Pure black backgrounds.
- White, high-contrast typography.
- Restrained cybersecurity red accents.
- Technical details inspired by monitoring systems and digital infrastructure.
- Sharp rectangular buttons.
- Minimal decoration and precise spacing.
- Subtle motion rather than excessive animation.

The reference is the visual starting point, not the entire website.

**Core design principle:** Make it easy for an analyst to understand what happened, inspect the evidence, evaluate the AI recommendation, and record a human decision.

## 2. Website Structure

ThreatIQ consists of an optional public landing page and the main authenticated-style investigation workspace. Authentication itself is outside the initial MVP.

### Routes

| Route | Page | Purpose |
|---|---|---|
| `/` | Dashboard | Overview of security alerts and investigation workload |
| `/investigations/:alertId` | Investigation | Detailed investigation of one alert |
| `/investigations/:alertId/history` | History | Assessment, decision, and audit timeline |
| `*` | Not Found | Recover from invalid routes |

The dashboard is the main application entry point. Do not force users through a long marketing page before they can investigate alerts.

If a landing page is implemented, it should be a separate, optional route and must not replace these application pages.

## 3. Design Tokens

### Colors

```css
:root {
  --bg: #000000;
  --surface: #0a0a0a;
  --surface-raised: #111111;
  --surface-hover: #191919;

  --border: #292929;
  --border-strong: #414141;

  --text-primary: #ffffff;
  --text-secondary: #c4c4c4;
  --text-muted: #858585;

  --accent-red: #c81b1c;
  --accent-red-hover: #b01617;
  --accent-red-soft: rgba(200, 27, 28, 0.12);

  --success: #65c58b;
  --warning: #e9b65b;
  --danger: #ff5a5f;
  --info: #80b7ff;
}
```

Use red for primary actions, active navigation, and important security indicators. Do not make every element red.

Use semantic colors consistently. For example, severity and workflow status must remain distinguishable even when they share a similar color.

### Typography

Use the typography established by the reference image.

- **Space Grotesk:** headings, buttons, navigation labels, and prominent values.
- **JetBrains Mono:** alert identifiers, timestamps, technical metadata, source labels, and compact data values.

Recommended font loading:

```css
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap');

body {
  font-family: 'Space Grotesk', sans-serif;
  background: var(--bg);
  color: var(--text-primary);
}

code,
.mono,
.timestamp,
.alert-id {
  font-family: 'JetBrains Mono', monospace;
}
```

For production, self-host the fonts if appropriate. If external font loading fails, use system fallbacks.

### Layout

- Desktop application sidebar: approximately 220–250px.
- Main content: flexible remaining width.
- Page padding: approximately 28–36px on desktop.
- Section spacing: 24–32px.
- Compact table rows with sufficient text spacing.
- One-pixel borders for separation.
- Small corner radius only where needed for inputs or overlays; primary buttons remain square.
- Responsive layout for tablet and mobile.

The screenshot's fixed 1505 × 700 canvas is useful for recreating its landing-page composition, but **the actual application must be responsive and scrollable**. Investigation tables and evidence timelines cannot be restricted to a full-screen, no-scroll canvas.

## 4. Global Application Layout

Every application page uses a consistent shell.

```text
┌────────────────────────────────────────────────────────────────────┐
│ THREATIQ                                            DEMO ENVIRONMENT│
├──────────────────┬─────────────────────────────────────────────────┤
│                  │                                                 │
│  Dashboard       │  Page title                                     │
│                  │  Supporting description                         │
│  Investigations  │                                                 │
│                  │  Main page content                              │
│  History         │                                                 │
│                  │                                                 │
│                  │                                                 │
│                  │                                                 │
│  SYSTEM STATUS   │                                                 │
└──────────────────┴─────────────────────────────────────────────────┘
```

### Sidebar

The sidebar contains:

1. ThreatIQ logo and product name.
2. Dashboard.
3. Investigations.
4. History, accessible from an investigation or through a dedicated history view.
5. A visible `DEMO ENVIRONMENT` indicator when running the synthetic demo.

The active route uses a restrained red indicator and stronger text contrast.

The sidebar may collapse on smaller screens. On mobile, use a menu overlay instead of forcing the desktop sidebar into a narrow column.

### Top bar

The top bar contains:

- Current page or breadcrumb.
- Environment indicator.
- Optional refresh action where appropriate.

Do not display fake user profiles, online teammates, or notification counts that are not backed by implemented functionality.

## 5. Page One — Dashboard

**Route:** `/`

The dashboard is the primary workspace, not a marketing homepage.

### Header

Display:

**Security overview**

Supporting text:

`Review alerts. Investigate evidence. Make informed decisions.`

Place a refresh control on the right if it actually reloads the data.

### Summary metrics

Display four compact summary values:

- Total alerts.
- Unresolved alerts.
- High and critical alerts.
- Awaiting review.

These values must be calculated from the actual alert records and current workflow states.

Do not use the reference image's `300+ Clients`, `99% Satisfaction`, or `$5M+ Revenue` figures in the application. They are reference-site content, not verified ThreatIQ metrics.

### Alert filters

Provide:

- Search by alert title or identifier.
- Severity filter.
- Workflow-status filter.
- Clear filters action.

Filters must affect the displayed results, not merely decorate the interface.

### Alert table

Recommended columns:

| Column | Content |
|---|---|
| Alert | Title and alert identifier |
| Severity | Low, medium, high, critical |
| Source | Originating system or source |
| Status | New, investigating, awaiting review, resolved |
| Created | Timestamp |
| Action | Open investigation |

Each row opens the corresponding investigation page.

Use a dark table with subtle horizontal dividers. Avoid turning every row into a separate card.

### Dashboard states

Implement:

- Loading state.
- Empty state.
- No matching filters state.
- Backend error state.
- Refresh failure state.

For an empty dataset, explain that no alerts are currently available. Do not insert fake records into the UI without identifying them as synthetic demo data.

## 6. Page Two — Investigation Workspace

**Route:** `/investigations/:alertId`

This is the most important page in ThreatIQ. Prioritize its functionality over decorative landing-page effects.

### Page header

Show:

- Breadcrumb back to Dashboard.
- Alert title.
- Alert ID.
- Severity.
- Workflow status.
- Creation timestamp.
- Link to investigation history.

Example:

```text
Dashboard / Investigations / AL-1042

Suspicious outbound connection

AL-1042   HIGH   AWAITING REVIEW

Created: 28 Oct 2026, 14:32 UTC
```

The example is illustrative and must not be treated as a real incident.

### Main layout

Use a two-column desktop layout:

```text
┌──────────────────────────────────────────────────────────────────┐
│ Alert title                         HIGH · AWAITING REVIEW        │
│ Alert ID · Source · Timestamp                                    │
├──────────────────────────────────┬───────────────────────────────┤
│                                  │                               │
│ ORIGINAL ALERT                   │ AI ASSESSMENT                 │
│                                  │                               │
│ Description                      │ Suggested classification     │
│ Raw alert fields                 │ Summary                       │
│                                  │ Evidence references           │
│                                  │ Missing information           │
│                                  │ Recommended next steps        │
│                                  │                               │
├──────────────────────────────────┤                               │
│ SUPPORTING EVIDENCE               │                               │
│                                  │                               │
│ Alert facts                      │                               │
│ Related incidents                │                               │
│ External sources, if enabled     │                               │
├──────────────────────────────────┴───────────────────────────────┤
│ HUMAN REVIEW                                                     │
│ Decision · Optional note · Submit decision                       │
└──────────────────────────────────────────────────────────────────┘
```

On narrow screens, stack the sections vertically in the order shown.

### A. Original alert

Display the original alert separately from the AI assessment.

Include:

- Alert description.
- Severity.
- Source.
- Timestamp.
- Relevant available fields.
- Alert identifier.

Do not rewrite the original alert and present the rewritten text as original evidence.

### B. AI assessment

Display the model's output in a clearly labelled section.

Supported classifications:

- `likely_true_positive`
- `likely_false_positive`
- `needs_review`

Translate these values into readable labels in the UI without changing their underlying API values.

Include:

1. **Suggested classification** — the model's recommendation.
2. **Summary** — a plain-language explanation.
3. **Supporting evidence** — references to available source records.
4. **Missing information** — details that prevent a stronger assessment.
5. **Recommended next steps** — suggestions for analyst investigation.

Use a primary action such as `Analyze alert` before an assessment exists.

While the request runs, show progress and prevent accidental duplicate submissions where appropriate.

If the model fails, show an error and a retry action. Do not substitute fabricated results.

### C. Supporting evidence

Separate evidence into clearly labelled groups:

- Facts from the original alert.
- Related historical incidents.
- External threat intelligence, if enabled and available.

Every evidence item must identify its source.

When no related incidents are found, show an explicit empty state. Do not invent similar incidents.

Historical similarity is context, not proof that two incidents share the same cause.

### D. Missing information

Use a dedicated section to explain what the assessment cannot establish.

Examples of possible missing information include:

- Incomplete connection details.
- Missing asset context.
- No related historical records.

These examples should appear only when they reflect the actual alert or model output.

### E. Recommended next steps

Present model-suggested actions as investigation guidance, not executed remediation.

The interface must not automatically block IP addresses, disable accounts, delete files, or change security controls.

### F. Human review

Display a distinct review section below the evidence and assessment.

Provide three decision options:

- `True Positive`
- `False Positive`
- `Needs Further Review`

Include an optional reviewer-note field and a submit button.

The submission must persist the decision through the backend API.

After success, show the saved decision and its timestamp.

**Critical distinction:** The AI recommendation and the human decision are separate records. Never imply that the model's suggestion is the analyst's final decision.

## 7. Page Three — Investigation History

**Route:** `/investigations/:alertId/history`

This page makes the investigation traceable.

### Header

Display the alert title, alert ID, and a link back to the investigation.

### Timeline

Show chronological events such as:

- Alert created.
- Assessment started.
- Assessment completed.
- Assessment failed.
- Human decision recorded.
- Workflow status changed.

Each event should include:

- Event type.
- Timestamp.
- Actor type, where available.
- Relevant details.

Example:

```text
28 Oct 2026 · 14:32 UTC

ASSESSMENT COMPLETED

AI assessment saved.
Suggested classification: Needs Review.

28 Oct 2026 · 14:35 UTC

DECISION RECORDED

Human decision: Needs Further Review.
```

The entries above are examples, not actual application records.

Read history from the backend. Do not generate timeline events on the frontend simply to make the page look populated.

If there is no history, display a clear empty state.

Do not describe the history as tamper-proof unless cryptographic integrity protections have actually been implemented.

## 8. Optional Public Landing Page

A landing page is secondary to the working application.

If implemented, preserve the supplied reference's visual identity:

- Black full-screen hero.
- Technical red video atmosphere.
- White Space Grotesk headline.
- JetBrains Mono supporting text.
- Sharp red CTA buttons.
- Minimal navigation.
- Restrained entrance animation.

Replace the reference's generic security-marketing content with accurate ThreatIQ messaging.

Suggested headline:

**Investigate security alerts with evidence, not guesswork.**

Suggested supporting text:

`AI-assisted investigation. Traceable evidence. Human-led decisions.`

Primary CTA: `Open dashboard`

Secondary CTA: `Explore workflow`

Do not use fabricated customer counts, satisfaction percentages, revenue, testimonials, or enterprise logos.

If the optional background video is retained, provide a static fallback, respect reduced-motion settings, and ensure that it never makes the investigation interface harder to read.

## 9. Interaction Rules

### Navigation

- Dashboard opens `/`.
- Opening an alert navigates to `/investigations/:alertId`.
- History opens `/investigations/:alertId/history`.
- Back navigation returns to the previous meaningful page.
- Invalid alert IDs display a not-found state.

### Analysis

- Clicking `Analyze alert` calls the backend.
- The interface shows a loading state.
- Valid results are displayed and persisted.
- Errors are visible and recoverable.
- Retrying does not falsely imply the earlier request succeeded.

### Review

- The analyst chooses a decision.
- The note is optional.
- Invalid submissions are rejected with useful feedback.
- Successful decisions are persisted.
- The history is refreshed or updated from the saved result.

### Hover and focus

- Red hover states are subtle.
- Keyboard focus is clearly visible.
- All interactive elements have accessible labels.
- Color is never the only way to communicate severity or status.

## 10. Responsive Behavior

### Desktop

- Persistent sidebar.
- Two-column investigation workspace.
- Full alert table.
- Comfortable space for evidence and assessment.

### Tablet

- Narrower sidebar or collapsible navigation.
- Reduced horizontal padding.
- Investigation columns shrink or stack when necessary.
- Tables may scroll horizontally where appropriate.

### Mobile

- Navigation becomes a menu overlay.
- Investigation sections stack vertically.
- Buttons remain easy to tap.
- Long identifiers and technical fields wrap or scroll safely.
- No horizontal page overflow.
- Tables use a responsive layout or a contained horizontal scroller.

The reference landing page uses a fixed-canvas scaling technique. Do not apply that technique to the entire application: real investigation content needs natural document flow and vertical scrolling.

## 11. Accessibility

- Maintain readable text contrast.
- Use semantic headings and buttons.
- Associate labels with form controls.
- Provide keyboard navigation.
- Add visible focus indicators.
- Support reduced motion.
- Do not rely on color alone for severity.
- Announce relevant loading and submission feedback to assistive technologies.
- Keep errors close to the affected control or section.

## 12. Implementation Rules

Follow the existing project structure and use the current stack.

- React and TypeScript for the frontend.
- Tailwind CSS for styling.
- FastAPI for backend endpoints.
- Existing API client in `frontend/src/services/api.ts`.
- Shared frontend types in `frontend/src/types/`.
- Existing database entities and API schemas.
- Real Nebius inference using a verified, eligible NVIDIA model.

Do not introduce another frontend framework or duplicate backend endpoints solely for visual design.

The UI must use actual API responses for alerts, assessments, review decisions, and history.

## 13. Build Priority

### P0 — Required for the core application

- [ ] Global application shell.
- [ ] Dashboard with database-backed alerts.
- [ ] Search and filters.
- [ ] Investigation detail page.
- [ ] Real AI analysis request.
- [ ] Structured assessment display.
- [ ] Traceable evidence section.
- [ ] Human decision form.
- [ ] Persisted review decisions.
- [ ] Investigation history.
- [ ] Loading, empty, and error states.
- [ ] Responsive layouts.

### P1 — Useful improvements

- [ ] Historical incident similarity.
- [ ] Optional external threat intelligence.
- [ ] Better timeline filtering.
- [ ] Downloadable investigation report.
- [ ] Refined motion and visual transitions.

### P2 — Future scope

- [ ] Authentication and role-based access.
- [ ] Team assignments.
- [ ] Enterprise security-platform integrations.
- [ ] Advanced analytics.
- [ ] Automated response workflows, subject to separate safety and authorization design.

## 14. Final Design Principle

ThreatIQ should look like the reference image at first glance, but behave like a complete cybersecurity investigation product.

**Visual identity:** Black, white, technical typography, restrained red.

**Product experience:** Alerts → AI assessment → Evidence → Human decision → Audit history.

**Success criterion:** An analyst can understand an alert, examine the supporting evidence, see what remains uncertain, record a decision, and revisit the investigation history without leaving the application.