# Microsoft Entra ID single sign-on

Optional. With nothing configured, ThreatIQ behaves exactly as before (email + password). When configured, the sign-in page also shows **Sign in with Microsoft**; password sign-in keeps working for existing accounts.

## How it works
- **Flow:** OpenID Connect *authorization code with PKCE*, run by the backend as a confidential client using Microsoft's `msal` library. The browser is only redirected; no Microsoft token is sent to it, and none is stored (the MSAL token cache is disabled, the refresh token is discarded).
- **Token validation (backend):** MSAL 1.38+ no longer validates ID tokens, so `app/services/entra_service.py` does: RS256 signature against Microsoft's published keys (JWKS), audience = your client ID, `exp`/`iat` with 2 min leeway, issuer = `<authority host>/<tid>/v2.0`, nonce (replay), and `tid` against the configured/bound tenant. `state` and the PKCE verifier are checked by MSAL. The in-flight state lives in a short-lived (10 min), encrypted, `HttpOnly` cookie, so a callback from a different browser is refused.
- **Session:** after validation the backend issues the same session cookie + CSRF token as password sign-in, so every existing authorization rule applies unchanged.

## Mapping users to organizations and roles
| Concern | Rule |
|---|---|
| **Organization** | The token's `tid` (tenant) must equal the `entra_tenant_id` of an organization. Bind it with the operator CLI (below). The binding is deliberately **not** exposed in the API or UI, so an organization admin cannot claim a tenant. An unbound tenant is refused; no organization is created. |
| **User identity** | Matched on (`tid`, `oid`), the immutable directory object ID, stored in `external_identities`. Email is never used to find or merge accounts (email claims are mutable). |
| **First sign-in** | If `ENTRA_AUTO_PROVISION=true`, a user is created with an unusable random password (password sign-in is impossible for them) and a membership in the bound organization. If the email already belongs to a local account the sign-in is **refused** (`conflict`); accounts are never silently merged. |
| **Role** | From the token's `roles` claim (Entra *app roles*): `ThreatIQ.Owner`, `ThreatIQ.Admin`, `ThreatIQ.Analyst`, `ThreatIQ.Viewer` (the `ThreatIQ.` prefix and case are optional). The highest wins and is synced on every sign-in. No role claim → `ENTRA_DEFAULT_ROLE` for new users; existing users keep their role. The last owner is never demoted. |
| **Removed members** | If an admin removes someone in ThreatIQ, their Entra identity is *not* re-added on the next sign-in (`not_member`). Remove the Entra app-role assignment too. |
| **Tenant isolation** | Unchanged: the organization comes from the server-side session; every query filters by it. SSO only decides which organization a new session starts in. |

## Setup (manual steps)
1. **Entra admin center → App registrations → New registration.** Supported account types: *this organizational directory only* (single tenant, recommended). Redirect URI: platform **Web**, value = your `ENTRA_REDIRECT_URI`:
   - local dev: `http://localhost:5173/api/v1/auth/sso/entra/callback` (through the Vite proxy so cookies stay same-origin; use `localhost`, not `127.0.0.1`)
   - production: `https://<your-host>/api/v1/auth/sso/entra/callback` (https is enforced in production)
2. Note **Application (client) ID** and **Directory (tenant) ID**.
3. **Certificates & secrets → New client secret**; copy the *Value* immediately. Note its expiry date: Microsoft sign-in stops working when the secret lapses.
4. **API permissions:** the default `User.Read` (delegated) is enough. No admin consent needed for `openid`, `profile`, `email`.
5. **Token configuration → Add optional claim → ID:** `email`. (Without an `email` or UPN-shaped `preferred_username` claim, sign-in fails with `no_email`.)
6. **App roles → Create app role** for each of Owner/Admin/Analyst/Viewer: value `ThreatIQ.Owner` etc., allowed member type *Users/Groups*. Then **Enterprise applications → ThreatIQ → Users and groups** to assign people. Strongly recommended: Enterprise application → Properties → **Assignment required = Yes**, so only assigned people can sign in at all.
7. Set the variables in `backend/.env.local` (see `backend/.env.example`): `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `ENTRA_TENANT_ID`, `ENTRA_REDIRECT_URI` (and optionally `ENTRA_DEFAULT_ROLE`, `ENTRA_AUTO_PROVISION`). Set all four or none; partial configuration stops the server at startup with a clear message.
8. Install the new dependencies and apply the migration (runs automatically at startup): `pip install -r requirements.txt`.
9. **Bind the tenant to an organization** (the organization must exist: register it first):
   ```powershell
   cd backend
   .venv\Scripts\python -m app.cli sso-list
   .venv\Scripts\python -m app.cli sso-bind <organization-slug> <tenant-id-guid>
   ```
   `sso-unbind <slug>` stops new SSO sign-ins; existing sessions live until they expire or are revoked.
10. Restart the backend and open the sign-in page.

**Multi-tenant** (one ThreatIQ serving several customers' Entra tenants): register the app as multi-tenant, set `ENTRA_MULTI_TENANT=true` and leave `ENTRA_TENANT_ID` empty, then `sso-bind` each customer's organization to their tenant ID. Each customer's admin must grant consent. A tenant with no binding is refused.

## Error codes shown on the sign-in page
`denied`, `expired`, `tenant_not_allowed`, `not_member`, `not_provisioned`, `no_email`, `conflict`, `disabled`, `not_configured`, `failed`. The server logs the precise reason; the browser never receives raw identity-provider text.

## Verification status
Verified locally: configuration validation; the migration (fresh SQLite); ID-token validation against locally generated RSA keys (accepts a valid token; rejects wrong audience, expired, wrong nonce, wrong issuer, unconfigured tenant, missing `oid`, a forged signature and an HS256 token); tenant binding rules; provisioning, role sync, e-mail-collision refusal and removed-member refusal; the authorization URL MSAL produces (PKCE S256, state, hashed nonce) against Microsoft's public `organizations` authority.

**Not verified:** a real sign-in against a live Entra tenant (none was available): the redirect round-trip, real JWKS retrieval, and consent screens. Run through the setup once in a test tenant before relying on it. Not implemented: group-based role mapping (use app roles), linking an existing password account to Microsoft, SCIM provisioning/deprovisioning, front/back-channel logout (signing out of ThreatIQ does not sign out of Microsoft), MFA enforcement inside ThreatIQ (use Conditional Access in Entra).
