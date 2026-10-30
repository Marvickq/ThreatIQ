# Security model and configuration

No compliance certification (SOC 2, ISO 27001, GDPR, HIPAA, ...) is claimed. This describes the controls that exist and their limits.

## Authentication and sessions
- Local accounts; passwords hashed with **Argon2id**; minimum length 10 (`PASSWORD_MIN_LENGTH`).
- Opaque 256-bit session tokens; only their SHA-256 is stored, so a database leak does not yield usable sessions. Sessions expire (`SESSION_TTL_HOURS`, default 12), can be listed and revoked, and are all revoked on password change.
- Cookie: `HttpOnly`, `SameSite=Lax`, `Secure` when `APP_ENV=production`.
- **CSRF:** unsafe methods with cookie auth must send `X-CSRF-Token` equal to the session's token (double-submit). API-key requests (Bearer) are not cookie-based and are exempt.
- **Login abuse:** per-IP and per-email rate limits; after `LOGIN_MAX_FAILURES` (5) failures the account locks for `LOGIN_LOCKOUT_MINUTES`. Unknown emails get the same response and similar timing as wrong passwords.
- **Microsoft Entra ID SSO** (optional): backend-run OIDC authorization-code + PKCE; ID tokens are validated on the server (signature, issuer, audience, expiry, nonce, tenant); users are matched on (tenant, object ID), never email; the tenant-to-organization binding is operator-only. Details and what is unverified: `docs/sso-entra.md`.
- Not implemented: MFA inside ThreatIQ (use Entra Conditional Access for SSO users), email verification, invitations, self-service password reset.

### Account recovery
No email is sent, so recovery needs server access: `python -m app.cli reset-password user@example.com` sets a random temporary password, unlocks the account, signs out every session and writes an audit event to each of the user's organizations. The user then changes the password in Settings → Security. Run it only after verifying the person's identity out of band.

- **Metrics:** `/api/v1/metrics` requires `METRICS_TOKEN` when set; in production it is **disabled (404) unless a token is set**.

## Organizations, roles and tenant isolation
- Roles: **viewer** (read), **analyst** (+ status, assignment, decisions, analysis), **admin** (+ integrations, API keys, members, settings, audit), **owner** (+ granting owner). You cannot grant or change a role above your own; the last owner cannot be removed or demoted.
- The organization and role are derived **on the server** from the session or API key and re-read on every request, so removals and role changes apply immediately. Nothing the browser sends can select an organization.
- Entra sign-in can only start a session in the organization bound to the token's tenant (`organizations.entra_tenant_id`, set with `python -m app.cli sso-bind`).
- Every query on tenant data filters by `organization_id`. Another organization's records are reported as *not found*, never *forbidden*. Isolation is enforced in the application layer; there is no PostgreSQL row-level security yet.
- Human review decisions require a signed-in user; **API keys can never make decisions**.

## API keys
256-bit random, stored as SHA-256 hashes, shown once, scoped (`alerts:read`, `alerts:write`, `ingest:write`), expiring (default 90 days), revocable, with `last_used_at` and a use counter. Revocation applies immediately.

## Data protection
- Alert text, raw events, retrieved documents and provider results are **untrusted**: stored as data, rendered as plain text, and sent to the model only inside delimited evidence blocks that cannot be closed by their own content.
- **External sharing is opt-in.** NVD/VirusTotal lookups send only identifiers (CVE IDs / indicator values), only after an admin enables it. Alert descriptions are never sent to third parties. The model provider (Nebius) *does* receive the alert and evidence being analyzed — that is the purpose of the feature; do not enable analysis for data you may not send to it.
- Integration credentials are encrypted at rest with a key derived from `SECRET_KEY` (Fernet) and never returned by the API. Rotating `SECRET_KEY` makes them unreadable.
- Logs are structured JSON with a request ID and **redaction** of API keys, bearer tokens, passwords, cookies and CSRF tokens. Error responses never include stack traces.
- At rest/in transit encryption depends on deployment: the Terraform enables RDS/ElastiCache/S3 encryption and TLS on the load balancer. Nothing here encrypts data inside the application database beyond integration credentials.

## Network and platform controls
- Strict CORS (explicit origins; `*` refuses to start), security headers on every response, request-size limits, a request timeout, rate limiting (in-process, or Redis when configured), `Retry-After` on 429.
- Outbound integration URLs go through SSRF validation (see `integrations.md`).
- Production configuration is validated at startup and refuses to run with SQLite, the default `SECRET_KEY`, or demo data enabled.
- Audit events are append-only through the application and cover sign-ins, password changes, member/role changes, API-key and integration changes, exports, decisions and status changes. They are **not tamper-proof**: a database administrator can alter them.

## Data export, retention, deletion
- Admins can export organization data (`GET /api/v1/organization/export`, audited). Credentials, key hashes and session tokens are excluded.
- `retention_days` records policy and `GET /api/v1/organization/retention` reports how many resolved alerts exceed it. **No automatic or manual deletion workflow exists**: ThreatIQ never deletes security records. Archive or purge at the database level according to your own policy, after exporting.

## Known limitations
No MFA; no OIDC; no email; isolation without RLS; in-process rate limits are per instance unless Redis is configured; the `X-Forwarded-For` header is trusted for client IPs, so run behind a proxy you control; no malware scanning of anything; prompt-injection defenses reduce but cannot eliminate risk, which is why the AI can only advise and every consequential decision is human.
