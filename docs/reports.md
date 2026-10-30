# Incident investigation reports

A report is a PDF snapshot of one alert's investigation, built on the server from records ThreatIQ already stores: the alert, its indicators, evidence (CISA KEV, NVD, VirusTotal, historical cases), AI assessments, analyst decisions and the audit trail. Nothing is invented; every empty section says what is missing.

## Using it
Alert detail page, **Investigation report** section (the **Report** button in the header jumps to it): choose a classification, **Generate report**, then **Download PDF**. The history lists every attempt, including failed ones.

## API
| | |
|---|---|
| `POST /api/v1/alerts/{id}/reports` body `{"classification": "Public\|Internal\|Confidential\|Restricted"}` | Generate and store a report (201). Needs `alerts:write` (analyst or an `alerts:write` API key). 20 per minute per organization. |
| `GET /api/v1/alerts/{id}/reports` | Generation history, newest first. Needs `alerts:read`. |
| `GET /api/v1/alerts/{id}/reports/{report_id}/download` | The stored PDF. Needs `alerts:read`. |

Another organization's alert, or a report that does not belong to that alert and organization, returns 404 exactly like a missing one. A failed generation returns `500 REPORT_GENERATION_FAILED`, is kept in the history with an error code only, and changes nothing on the alert.

## Contents
Cover; 1 Executive summary; 2 Alert details; 3 Evidence and threat intelligence (indicators, provider lookups, historical cases, evidence register with hashes and retrieval times); 4 AI investigation (facts, interpretation, missing information, next steps, citations re-checked against stored evidence); 5 Analyst review; 6 Investigation timeline (from the append-only audit log); 7 Limitations and disclaimer.

## Behaviour worth knowing
- **Snapshot.** The PDF is stored (`investigation_reports` table) and downloads return exactly what was generated. Later decisions appear only in a newly generated report.
- **"Accepted / rejected" is derived.** ThreatIQ does not store an accept/reject action. The report compares the recorded decision with the linked AI suggestion and says "Consistent with" or "Differs from ... not adopted".
- **No secrets.** Integration names and kinds appear; endpoints, credentials, raw source events and API keys never do. Provider error text is redacted.
- **Fonts.** Bitstream Vera, embedded from the ReportLab package. Characters it cannot draw (for example CJK, Cyrillic) print as `?` and the report says how many.
- **Audit.** `report_generated`, `report_downloaded` and `report_failed` are recorded on the alert (IDs and counts only).

## Not verified
Rendered and parsed in automated tests and inspected as page images, but not opened in Acrobat, Preview or a printer; not run in the Docker image; stored in the database (not S3), so very large histories grow the database.
