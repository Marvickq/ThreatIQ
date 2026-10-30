# Security overview dashboard

Every number, chart and queue is computed on request from persisted alerts, review decisions and audit events. Nothing is hardcoded or precomputed on the client.

## Endpoints (all under `/api/v1/dashboard`, permission `alerts:read`, organization taken from the session or API key)
| Endpoint | Returns |
|---|---|
| `GET /summary` | total, unresolved, high+critical, awaiting review, no-decision-yet; 8 most recent alerts; 10 most recent alert activity events; `sources` (whole-organization real/demo counts) |
| `GET /severity` | count per severity (critical, high, medium, low; zeros included) |
| `GET /daily` | alerts created per **UTC** calendar day for the last 14 days (today included), zero days included, oldest first |
| `GET /queues` | investigation queues with a count and the alert-list query that reproduces it |

## Shared filters (identical on all four, and on `GET /alerts`)
`data_scope` (`real` default · `demo` · `all`), `severity`, `status`, `assigned_to` (user ID · `unassigned` · `me`), `review_state` (`unreviewed` · `reviewed` · `true_positive` · `false_positive` · `needs_further_review`). `review_state` comes from the **latest persisted review decision**, not from workflow status. The response echoes the filters it used. Queues apply the filters on top of their own definition; if the two contradict (e.g. status = Resolved with "Critical, still open") the count is 0 and the queue has no link.

## Real vs. demo data
Alerts loaded by "Load labelled demo data" are stored with `is_demo = true`. The dashboard defaults to **real alerts only**; demo alerts are excluded and the page says how many were hidden. Demo data is shown only on explicit choice (`demo` or `all`), with a visible banner, and demo rows carry a *Demo* badge. Existing demo-looking rows from older versions were backfilled by migration 0002.

## Dates
Stored in UTC. Daily buckets use whole UTC days (`date(created_at AT TIME ZONE 'UTC')` on PostgreSQL), regardless of the database or browser time zone.

## Refresh
The page re-queries when: an alert is created or updated by anyone in the organization (live event), a decision is recorded, an alert is assigned or its status changed (including bulk), an analysis/enrichment job finishes or fails, demo data is loaded, the Refresh button is pressed, and every 60 s. Each panel has its own loading, empty and error state; a failed refresh keeps the last data with a "may be out of date" banner.

Live events need the SSE stream (`/events/stream`); if it is blocked by a proxy the 60 s poll still applies.
