# Legacy test suite (V1, single-tenant API) — not maintained

These tests were written for ThreatIQ V1 (unauthenticated, single organization, `/alerts/counts`,
`/related-incidents` returning static incidents, `seed_demo_alerts(session)` with no organization).
The V2 API requires authentication and organization scoping, so they no longer run against it and
were **not** updated: the V2 work was done under an instruction not to implement automated testing.

They are kept for reference only (history of what V1 covered). V2 was verified with throwaway scripts
and browser runs that are not part of the repository; see `wer/tracker.md` for exactly what was verified.
