# Runbook: Microsoft Entra ID registration (production auth)

How to point Helix at a real **Microsoft Entra ID** tenant for the M5 Azure
deploy, replacing the local dev OIDC issuer (`apps/dev-idp`).

**Why this is almost config-only.** Both `apps/edge` (app-user SSO) and
`apps/portal` (bearer-JWT API auth) speak generic OIDC, read
issuer/client/audience from environment variables, and use OIDC discovery — no
endpoints are hardcoded. The portal verifier already reads Entra's `roles` claim
(`apps/portal/src/auth/verifier.ts`). So production auth is mostly: create the
registrations below, then set the env vars. Two small code additions were needed
where the dev IdP had been doing Entra's job for us, and both already landed:

- **Certificate (`private_key_jwt`) client auth** for the edge, for tenants that
  block client secrets (`apps/edge/src/auth/oidc.ts`, `buildClientAuth`).
- **Requesting the portal API scope** from the SPA + CLI so the access token is
  audienced to the portal, not Microsoft Graph (`packages/shared` →
  `portalApiScope`). See [the audience gotcha](#the-token-audience-gotcha-read-this).

## Decisions baked into this runbook

- **Portal admin gating via App Roles; per-app group visibility via security
  groups.** These are two different questions and, since
  [ADR-0040](../adr/0040-entra-group-visibility-directory-seam.md), two different
  answers. *Admin gating* stays on an App Role: `platform-admin` in the `roles`
  claim on the **portal** registration — human-readable, no GUIDs, no Graph, no
  P1 license when assigning individual users. *Per-app group visibility* uses
  **security groups** on the **edge** registration
  (`groupMembershipClaims: SecurityGroup`, GUIDs in the `groups` claim), because
  a role-per-group would make "scope this app to a group" an infrastructure
  deploy — relocating the problem the feature exists to solve. The two coexist on
  separate registrations and separate claims; the portal verifier unions them.
- **Single-tenant.** Only the org's own users sign in. Issuer is the **v2**
  endpoint: `https://login.microsoftonline.com/{tenantId}/v2.0`.
- **Pilot apps use `internal` or `password` visibility.** The only role plumbing
  this runbook needs is one `platform-admin` role for portal admin gating.
  Per-app **group visibility** (`visibility: group`) is a separate, later step —
  ADR-0040 and
  [`entra-group-claims-rollout.md`](entra-group-claims-rollout.md).

Substitute the real apex domain for `azx.helix.azxlabs.io` if it differs
(`docs/platform-architecture.md` §4.2).

---

## Part A — Three app registrations

Created in **Azure Portal → Microsoft Entra ID → App registrations**. They
mirror the three dev-idp clients in `apps/dev-idp/src/fixtures.ts`.

### Reg 1 — `helix-edge` (app-user SSO; confidential web client)

| Setting | Value |
| --- | --- |
| Supported account types | Single tenant |
| Platform | **Web** |
| Redirect URI | `https://auth.azx.helix.azxlabs.io/callback` (no port in prod) |
| Credentials | A **client secret** *or* a **certificate** (see below) → store in Key Vault, never in source |
| Token (ID) optional claims | Add `email`; ensure `name` + `preferred_username` are emitted |

**Client credential — secret or certificate.** The edge is the one confidential
client, so it authenticates itself at the token endpoint. Two supported forms:

- **Client secret** (simplest): _Certificates & secrets → New client secret_.
  Set `EDGE_OIDC_CLIENT_SECRET`.
- **Certificate / `private_key_jwt`** (use this if a tenant policy blocks client
  secrets — the "Client secrets are blocked by a tenant-wide policy" error):
  generate a keypair + self-signed cert, upload the **public cert** under
  _Certificates & secrets → Certificates → Upload certificate_, and give the
  edge the **private key + cert** via `EDGE_OIDC_CLIENT_PRIVATE_KEY` +
  `EDGE_OIDC_CLIENT_CERTIFICATE`. The edge signs the client assertion and sets
  the cert's `x5t` thumbprint so Entra matches the uploaded key
  (`apps/edge/src/auth/oidc.ts`, `buildClientAuth`). Set **exactly one** of the
  two forms — both together is a config error.

  Generate a throwaway cert with:

  ```bash
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout edge-key.pem -out edge-cert.pem -days 365 -nodes \
    -subj "/CN=helix-edge"
  # Upload edge-cert.pem to Entra; feed both PEMs to the edge (see Part B).
  ```

  RSA keys work too (`-newkey rsa:2048`); the edge picks RS256/ES256 from the
  cert's key type automatically.

- PKCE is used by the edge automatically even though this client is
  confidential (`apps/edge/src/auth/oidc.ts`). Entra accepts it.
- The edge reads only the **ID token** and derives display name from
  `name → preferred_username → email`. `preferred_username` (the UPN) is always
  present in v2, so a missing `email` degrades gracefully.
- **No app roles here, ever.** `visibility: group` reads security groups, not App
  Roles (ADR-0040 decision 1), so the later step adds
  `groupMembershipClaims: SecurityGroup` to this registration rather than an
  `appRoles[]` entry per group. See
  [`entra-group-claims-rollout.md`](entra-group-claims-rollout.md).

### Reg 2 — `helix-portal` (portal SPA + the API its tokens target)

This single registration is both the SPA client and the protected API (its own
audience) — the simplest topology.

| Setting | Value |
| --- | --- |
| Supported account types | Single tenant |
| Platform | **Single-page application (SPA)** |
| Redirect URI | `https://portal.azx.helix.azxlabs.io/auth/callback` |
| Expose an API → Application ID URI | `api://<helix-portal-client-id>` |

- Registering the redirect under the **SPA platform** makes Entra serve CORS on
  the token endpoint automatically (this replaces the dev-idp `clientBasedCORS`
  hack) and enforces PKCE.
- **Audience note:** the Application ID URI must be `api://<guid>` (Entra rejects
  the dev value `urn:helix:portal`; a verified custom domain also works). That
  URI is what the *scope* is built from — but `PORTAL_OIDC_AUDIENCE` (what the
  portal verifies) is the **bare GUID** once you use v2 tokens; see the gotcha
  below.

**Expose an API → Add a scope.** This is the delegated permission the SPA and
CLI request so their tokens target the portal. Fill the form:

| Field | Value |
| --- | --- |
| Scope name | **`access`** → full scope is `api://<helix-portal-client-id>/access` |
| Who can consent? | **Admins and users** (pilot: lets users self-consent, nobody waits on an admin) |
| Admin consent display name | `Access the Helix portal API` |
| Admin consent description | `Allows the signed-in user to access the Helix portal API on their behalf.` |
| User consent display name | `Access the Helix portal` |
| User consent description | `Allows the app to access the Helix portal API on your behalf.` |
| State | **Enabled** |

#### The token-audience gotcha (read this — two traps)

The portal validates that every access token's `aud` equals `PORTAL_OIDC_AUDIENCE`
and `iss` equals the configured issuer. Two Entra defaults each break that; both
are one-time fixes and both bit us during the first login.

**Trap 1 — request the API scope.** Entra sets a token's `aud` from the resource
scope the client requests. A client asking for only `openid profile email` gets a
token audienced to Microsoft Graph, which the portal rejects — so the SPA and CLI
must request `api://<client-id>/access`. (The dev IdP hid this by forcing the
audience via resource indicators regardless of scope; Entra does not.) **Handled
in code:** `portalApiScope(audience)` (`packages/shared`) requests that scope
whenever the portal advertises a non-`urn:` (i.e. Entra) audience; it's a no-op
for the dev IdP's `urn:` audience.

**Trap 2 — use v2 tokens, and set the audience to the bare GUID.** Exposing a
custom API makes Entra issue **v1-format access tokens by default**
(`iss = https://sts.windows.net/<tenant>/`), which the portal — pinned to the v2
issuer — rejects with a 401 (login still works, because that uses the *ID* token,
which is already v2). Fix it on the helix-portal **Manifest**: set
`"requestedAccessTokenVersion": 2` (older manifest format:
`"accessTokenAcceptedVersion": 2`). **There is no UI toggle — it's manifest-only**,
or via CLI: `az ad app update --id <helix-portal-client-id> --set api.requestedAccessTokenVersion=2`.

> **Consequence that bites next:** a **v2** access token's `aud` is the **bare
> client-id GUID**, not the `api://` App ID URI (v1 was the opposite). So
> `PORTAL_OIDC_AUDIENCE` must be the **GUID** (`<helix-portal-client-id>`), not
> `api://…`. The *scope* you request stays `api://…/access`; only the resulting
> token's `aud` is the GUID. (`portalApiScope` normalizes either form, so a bare
> GUID audience still yields the `api://…/access` scope.)

**Define the admin role** (App roles → Create app role):

| Field | Value |
| --- | --- |
| Display name | Platform Admin |
| Allowed member types | Users/Groups |
| Value | **`platform-admin`** |
| Description | Helix platform administrators (approvals, secrets, admin pages) |

Then **Enterprise applications → helix-portal → Users and roles → Add user/role**
and assign yourself to **Platform Admin**. That is the entire groups/roles story
for M5. The `roles` claim is emitted in both ID and access tokens for this app,
so the portal sees `platform-admin` for assigned users.

> To reuse an existing org security group instead of listing individual users,
> assign the **group** to the role here — this requires an Entra ID **P1**
> license.

### Reg 3 — `azx-cli` (CLI device-code; public client)

| Setting | Value |
| --- | --- |
| Supported account types | Single tenant |
| Redirect URI | none |
| Authentication → Allow public client flows | **Yes** (enables device-code grant) |
| API permissions | Delegated permission to `helix-portal`'s `access` scope (see below) |

**Add the API permission** (this is the Reg 3 half of the audience gotcha above):
_API permissions → Add a permission → **My APIs** → `helix-portal` → Delegated
permissions → check **`access`** → Add._ The CLI's access token then carries
`aud = <helix-portal-client-id>` (the bare GUID, with v2 tokens) and the user's
`roles`.

**Admin consent is optional**, because the `access` scope is set to "Admins and
users" can consent. The "Grant admin consent for \<tenant\>" button is greyed out
unless you hold a directory admin role (Global / Application / Cloud Application
Admin) — that's expected, not a blocker. Without it, the user simply gets a
one-time browser consent prompt during `helix login` (device flow) and approves
"Access the Helix portal." Granting admin consent only pre-approves it tenant-wide
so nobody is ever prompted. A permission status of "Not granted for \<tenant\>"
is fine.

> **Exception:** if the tenant has disabled user consent org-wide, first login
> fails with `AADSTS65001` / an "approval required" screen — then an admin must
> grant consent. Otherwise user consent just works.

> **The SPA (Reg 2) does NOT need this pre-added.** It obtains the same `access`
> scope by *dynamic consent* at login (the user consents in the browser the first
> time). Only the CLI's device-code flow needs the permission configured ahead of
> time.

> Optional simplification: Reg 2 and Reg 3 can be merged into one registration
> with both an SPA redirect and public-client-flows enabled. Kept separate here
> for least-privilege clarity.

### Admin consent

Tenant admin consent for the API scope is **optional** (the scope is
user-consentable) — granting it once just spares users the individual consent
prompt. Requires a directory admin role; skip it if you don't have one (see Reg 3).
Conditional access / MFA are pure Entra policy and need no code
(`docs/platform-architecture.md` Appendix A, step 4).

---

## Part B — Environment wiring

Set these in the M5 ACA app configuration / Key Vault. **The dev
`docker-compose.yml` is not changed** — local dev keeps using `apps/dev-idp`.

> **Critical:** set `NODE_ENV=production` so the dev escape hatches hard-refuse
> at startup — `EDGE_OIDC_ALLOW_INSECURE` / `PORTAL_OIDC_ALLOW_INSECURE` and
> `PORTAL_DEV_TOKEN` all throw in production
> (`apps/portal/src/auth/verifier.ts`).

### Edge (`apps/edge/src/config.ts`)

| Var | Value |
| --- | --- |
| `EDGE_OIDC_ISSUER` | `https://login.microsoftonline.com/{tenantId}/v2.0` |
| `EDGE_OIDC_CLIENT_ID` | helix-edge client id (GUID) |
| `EDGE_OIDC_CLIENT_SECRET` | from Key Vault — **or** use the certificate pair below (set exactly one form) |
| `EDGE_OIDC_CLIENT_PRIVATE_KEY` | (cert auth) PKCS#8 private-key PEM, or base64-encoded PEM |
| `EDGE_OIDC_CLIENT_CERTIFICATE` | (cert auth) the matching X.509 cert PEM, or base64-encoded PEM |
| `EDGE_OIDC_GROUPS_CLAIM` | **`groups`** (security-group GUIDs — the code default; set it explicitly anyway, an empty group claim fails silently). Was `roles`; ADR-0040 flipped it. |
| `EDGE_OIDC_SCOPES` | `openid profile email` (drop the code default's `groups` — it is not a Graph delegated permission; group claims come from the registration, not a scope) |
| `EDGE_AUTH_SECRET` | fresh base64 ≥32 bytes (internal HKDF key, **not** an Entra secret) |
| `EDGE_OIDC_ALLOW_INSECURE` | unset |

Confirm the control-domain/port config produces the portless callback
`https://auth.<control domain>/callback` to match Reg 1 (`apps/edge/src/server.ts`,
`controlOrigin`).

### Portal (`apps/portal/src/plugins/auth.ts`)

| Var | Value |
| --- | --- |
| `PORTAL_OIDC_ISSUER` | `https://login.microsoftonline.com/{tenantId}/v2.0` |
| `PORTAL_OIDC_AUDIENCE` | the **bare** `<helix-portal-client-id>` GUID (v2 token `aud`; replaces `urn:helix:portal`) |
| `AZX_CLI_CLIENT_ID` | azx-cli client id (GUID) |
| `AZX_WEB_CLIENT_ID` | helix-portal client id (GUID) |
| `PORTAL_ADMIN_GROUP_ID` | **`platform-admin`** (the app-role value) |
| `PORTAL_OIDC_ALLOW_INSECURE` / `PORTAL_DEV_TOKEN` | unset |

The portal advertises issuer + client ids to the CLI and SPA via
`GET /api/v1/auth/config`, so `packages/cli` and `apps/portal-web` need **no**
build-time config — they discover everything at runtime.

---

## Local testing against real Entra

You can point a local edge/portal at the real tenant before the Azure deploy —
the best dress rehearsal. Keep `apps/dev-idp` as the default; this is opt-in.

**Add the local redirect URIs to the registrations** (alongside the prod ones —
Entra allows many per app):

| Registration | Platform | Local redirect URI(s) |
| --- | --- | --- |
| `helix-edge` | Web | `https://auth.local.helix.azxlabs.io:8080/callback` |
| `helix-portal` | SPA | `http://localhost:5173/auth/callback` and `http://localhost:3001/auth/callback` |
| `azx-cli` | — | none (device code) |

- `auth.local.helix.azxlabs.io` is **not** `localhost` to Entra, so it must be **https**
  (the dev mkcert wildcard cert already covers it). `http://localhost:*` is
  special-cased by Entra, so the portal SPA URIs need no TLS.

**Edge → Entra via the certificate**, without touching committed config: drop an
`apps/edge/.env.local` (gitignored via `.env.*`; loaded by `apps/edge/src/server.ts`,
where it **overrides** the devcontainer env). The cert lives in the gitignored
`.devcontainer/certs/`. Example:

```sh
# apps/edge/.env.local — repoints helix-edge at Entra; delete to fall back to dev-idp.
EDGE_OIDC_ISSUER=https://login.microsoftonline.com/<TENANT_ID>/v2.0
EDGE_OIDC_CLIENT_ID=<HELIX_EDGE_CLIENT_ID>
EDGE_OIDC_CLIENT_SECRET=          # empty: disables the dev secret so it doesn't collide with the cert
EDGE_OIDC_ALLOW_INSECURE=         # empty: Entra is https
EDGE_OIDC_CLIENT_PRIVATE_KEY=<base64 of .devcontainer/certs/entra-edge-key.pem>
EDGE_OIDC_CLIENT_CERTIFICATE=<base64 of .devcontainer/certs/entra-edge-cert.pem>
EDGE_OIDC_GROUPS_CLAIM=groups     # needs groupMembershipClaims: SecurityGroup on the registration
EDGE_OIDC_SCOPES=openid profile email
```

Then **restart the `dev:edge` VS Code task** (`tsx watch` reloads on file save but
**not** on env change, so a task restart is required after editing `.env.local`).

**Portal + SPA → Entra:** point the portal's `PORTAL_OIDC_ISSUER` /
`PORTAL_OIDC_AUDIENCE` / `AZX_CLI_CLIENT_ID` / `AZX_WEB_CLIENT_ID` /
`PORTAL_ADMIN_GROUP_ID` at the Entra values (Part B). The SPA and CLI need **no**
local config of their own — they read everything from the portal's
`GET /api/v1/auth/config` at runtime.

---

## Verification

1. **Discovery:** from the deploy environment,
   `curl https://login.microsoftonline.com/{tenantId}/v2.0/.well-known/openid-configuration`
   returns a doc advertising `device_authorization_endpoint`, `token_endpoint`,
   and `jwks_uri`.
2. **App-user SSO (edge):** browse to an `internal` pilot app → redirected to
   `auth.azx.helix.azxlabs.io` → Entra login (MFA per policy) → handoff → app loads with
   a `__Host-session` cookie. Confirm the display name resolves.
3. **Portal admin (web):** sign in at `portal.azx.helix.azxlabs.io`. A user assigned
   **Platform Admin** sees the approvals/secrets admin pages; an unassigned user
   does not (proves `roles` → `PORTAL_ADMIN_GROUP_ID` gating). A denied admin
   attempt logs `admin denied: …` with the principal + the expected role value.
4. **CLI:** `helix login` completes the device flow against Entra; `helix whoami`
   shows the identity; `helix deploy` succeeds (proves the access token `aud`
   matches `PORTAL_OIDC_AUDIENCE`).
5. **Escape hatches refuse:** the services boot with `NODE_ENV=production`, and
   setting any `*_ALLOW_INSECURE` / `PORTAL_DEV_TOKEN` would throw at startup.
6. **Local dev unaffected:** `pnpm dev:idp` plus the adversarial suite
   (`apps/edge/src/auth/adversarial.test.ts`) still pass — the dev issuer is
   untouched.

---

## Beyond this runbook

- **Per-app group visibility (`visibility: group`).** No longer deferred: the
  App-Role-vs-security-group question was settled empirically and security groups
  won ([ADR-0040](../adr/0040-entra-group-visibility-directory-seam.md), evidence
  in [`docs/reviews/2026-08-20-entra-group-permissions-probe.md`](../reviews/2026-08-20-entra-group-permissions-probe.md)).
  In short: `groupMembershipClaims: SecurityGroup` on the edge **and** portal
  registrations, `EDGE_OIDC_GROUPS_CLAIM=groups`, and **one** admin-consented
  Graph permission — `GroupMember.Read.All`, application, held by the portal's
  managed identity — so GUIDs can be resolved to names. Procedure:
  [`entra-group-claims-rollout.md`](entra-group-claims-rollout.md). It has a hard
  ordering gate; read §0 before touching the portal registration.
- **Microsoft Graph group resolution** is therefore *required*, not avoidable —
  security groups emit object GUIDs and Entra has no "emit display name" option
  for cloud-only groups. That resolver now exists: `packages/directory`
  (`searchGroups`/`getGroups`, portal-only, zero runtime dependencies), behind
  `GET /api/v1/directory/groups` and the Access tab's group picker. Without the
  grant it reports itself unavailable and the tab falls back to entering ids
  directly — the gate is unaffected either way.
- **Multi-tenant / IdP-agnostic customers** (`docs/platform-project-plan.md` §3).
