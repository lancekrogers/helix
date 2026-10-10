# Authentication

> **Related ADRs:** [ADR-0004](../adr/0004-auth-model.md) (edge-terminated auth) · [ADR-0024](../adr/0024-portal-cli-bearer-jwt-jwks.md) (portal/CLI JWT) · [ADR-0019](../adr/0019-subdomain-per-app-isolation.md) (subdomain isolation) · [ADR-0011](../adr/0011-in-memory-rate-limiting.md) (in-memory rate limiting) · [ADR-0007](../adr/0007-portal-authz-v0.md) (portal authz v0).

Helix has separate authentication paths for app users and portal/CLI users:

1. **App-user auth** (the edge) — how a person signing into a hosted app gets a session. This
   is the platform's most security-sensitive code (architecture §4.2 / Appendix A) and carries
   a dedicated adversarial test suite.
2. **Portal/CLI auth** (the control plane) — how a deploy or registry mutation is authorized,
   via a bearer JWT verified statelessly over the issuer's JWKS.

Both use the local OIDC issuer in development (see [dev-idp.md](./dev-idp.md))
and Entra in production. Issuer settings select the environment; see the
[Entra registration runbook](../runbooks/entra-app-registration.md).

---

## App-user auth (the edge)

**What it is.** A central OIDC callback on `auth.<control domain>` does the code exchange once; a
single-use **handoff token** carries the result to the app host on the apps domain, which mints a
`__Host-session` cookie backed by a server-side, revocable session row. In a single-domain install
the control and apps domains are the same, so this reads as today's `auth.<base>` → `<slug>.<base>`
flow. Every asset and `/_api/*` call on an app host then passes a per-request **session gate**.

### The flow (Appendix A, steps 1–8)

1. **`GET /start?app=<slug>&rd=<path>&silent=1`** on the auth host
   (`apps/edge/src/auth/routes/authHost.ts`) — validates the slug + return path (no open
   redirects), generates state/nonce/PKCE, stashes them in a signed `__Host-oidc-flow` cookie
   (10 min), and redirects to the IdP (`prompt=none` when silent-refreshing).
2. **`GET /callback`** on the auth host — verifies and burns the flow cookie, re-resolves the
   app (it may have been archived mid-flow), does the PKCE code exchange, extracts the
   principal id from the configured claim — Entra's `oid` by default,
   `EDGE_OIDC_PRINCIPAL_CLAIM` on an issuer whose stable id lives elsewhere (ADR-0048, as
   amended; a token without it fails the login, no fallback), plus `displayName` /
   `groups`, runs the **visibility check** (`visibilityAllows`), creates a
   **pending** session row (no `tokenHash` yet), mints the handoff JWS (`jti=sessionId`,
   `aud=appId`, ~30 s), and redirects to `<slug>/_auth/complete?token=…`.
3. **`GET /_auth/complete?token=…`** on the app host (`apps/edge/src/auth/routes/appHost.ts`) —
   verifies the handoff JWS (audience = appId, signature, expiry), then **atomically redeems**
   it: `UPDATE sessions SET tokenHash = $1 WHERE id = $2 AND appId = $3 AND tokenHash IS NULL`.
   The cookie value is freshly random (never the URL-borne token); it's stored only as a SHA-256
   hash. Sets `__Host-session` (HttpOnly, Secure, SameSite=Lax) and redirects to the original
   path.

Single-use is enforced two ways (defense in depth): the JWS `aud` check **and** the store's
atomic `appId`+`tokenHash IS NULL` predicate — either alone defeats replay and audience
confusion.

### Control and apps domains

An install may serve hosted apps on a **separate domain** from the control hosts (`auth.`,
`portal.`, `dev-api.`). The edge reads `EDGE_BASE_DOMAIN` as the apps domain and
`EDGE_CONTROL_DOMAIN` as the control domain (unset defaults to the apps domain — single-domain
layout). The portal reads `APP_PUBLIC_BASE` for app URLs and, when split,
`CONTROL_PUBLIC_BASE` for the control origin (unset defaults to `APP_PUBLIC_BASE`). Bicep sets both
from one parameter pair when `hostedAppsDomain` is configured.

**Host classification** (`apps/edge/src/routing/hosts.ts`): only `auth.<controlDomain>` is the
auth host. Under the apps suffix, `auth.<appsDomain>` is **platform**, never auth — the adversarial
tests pin that property. With `EDGE_LEGACY_APP_REDIRECT` on (split only), `<slug>.<controlDomain>`
classifies as `legacy-app` and may receive a 307 to the same path on the apps domain (GET/HEAD,
paths not starting with `_`).

**Which helper builds which URL** (`apps/edge/src/config.ts`): `controlOrigin(config, "auth" |
"portal" | "dev-api")` builds auth-host URLs — `/start`, the OIDC redirect URI, the vendor
`/connections/callback`, silent-refresh restarts. `publicOrigin(config, slug)` builds app origins —
the handoff target `/_auth/complete`, the Origin check, password login, consent popup targets.
`publicOrigin` throws if passed a reserved label (`auth`, `portal`, …) so unmigrated call sites
fail in tests rather than emitting `auth.<appsDomain>`.

The handoff redirect is a **cross-site top-level navigation** when the domains differ.
`SameSite=Lax` does not block it; cookies stay **host-only** (`__Host-`, no `Domain`), so their
scope does not widen. The Origin and Fetch Metadata guard (`apps/edge/src/auth/validate.ts`)
accepts only `same-origin`; both `same-site` and `cross-site` are refused, so moving a sibling
app from same-site to cross-site changes nothing for `/_api/*`.

**Boot rules:** `controlDomain` must be a valid hostname and must not be equal to, a subdomain of,
or a parent of `appsDomain` unless the two are equal. The edge cannot verify Public Suffix List
membership without a new dependency; it logs the split at boot and the operator documentation
states the requirement: a **delegated apps subdomain** only separates sites when that zone is
listed on the Public Suffix List.

**Recorded browser check (dev container, Chromium 156 headless):** navigation from
`<slug>.helix-apps.localhost` to `auth.local.helix.azxlabs.io` reported `Sec-Fetch-Site:
cross-site`. The same-site pair `apps.local.helix.azxlabs.io` with control
`local.helix.azxlabs.io` reported `same-site`; in that pair a `Domain=<control domain>` cookie set
from the app host was observed reaching `auth.<control>`. Only Chromium was measured.

**Not tested:** Safari ITP, Firefox ETP, and Chrome bounce-tracking mitigations on real domains; a
real Public Suffix List entry and live DNS delegation; certificate issuance and two wildcard
bindings on one Container App (**unverified in Azure**); the TLS what-if canary with two bindings;
certbot behind the firewall tier on a split install.

### The session gate (`apps/edge/src/auth/gate.ts`)

One indexed `SELECT` per request — no cache, so revocation is immediate (Appendix A.4). Key
behaviors:

- **Navigation vs. fetch.** `Sec-Fetch-Mode` is authoritative (Accept sniff as fallback). No
  session → a navigation **302s** to `/start`; a fetch gets **401** `{code: "unauthorized"}`.
  Misclassification fails safe.
- **Per-request visibility re-check.** `visibilityAllows(entry, session.groups)` runs against
  the **live** registry entry, so tightening an app from internal → group bites immediately
  (bounded by snapshot staleness). A silent refresh re-snapshots groups at the IdP.
- **Silent refresh.** Past `refreshDueAt`, navigations take the `/start?silent=1` detour;
  `/_api/*` fetches get **401** `{code: "refresh_required"}` (the stale group snapshot is an
  authorization boundary, not a hint); passive assets stay lenient until hard expiry.
- **The `Caller` seam.** `makeCallerResolver` wraps the gate with the `public`-app
  short-circuit: `public` apps yield an unauthenticated caller (`ANON_USER_OID = "anon"`) and
  skip the gate, while every other mode goes through it. This is the single identity seam the
  gateway keys off (see [llm-gateway.md](./llm-gateway.md), [app-data-gateway.md](./app-data-gateway.md)).
- **`public` visibility — anonymous tier.** Going public is a high-risk change that routes through
  the approval queue (`docs/design/approvals.md` §6.3); the **Access** tab on the app's portal
  page is the real switcher for it (reductions apply immediately, public opens a request). At the
  gateway the anonymous tier is **per-IP rate-limited** — `apps/edge/src/gateway/ipRateLimiter.ts`,
  a fixed-window limiter over the shared `CounterStore` (`counterStore.ts`) it shares with
  `loginThrottle.ts`, caps every anonymous `/_api/*`
  call per IP+app (`429 rate_limited`; `EDGE_ANON_RATE_LIMIT`/`EDGE_ANON_RATE_WINDOW_MS`).
  Authenticated callers are never limited here — they answer to per-app budgets.

### Other app-host endpoints

- **`GET /_api/me`** — returns `{user: {id, displayName, email}}` (Appendix A.6); a fetch with no
  session gets 401, not a redirect. `email` is the captured address claim and is **nullable, not
  optional** — the key is always present, and it is `null` for shared-password `Guest` sessions
  and for issuers that send no addressable claim. Still no `groups`: an app that could read the
  group snapshot could reimplement the visibility check the edge already made for it.
- **`POST /_auth/logout`** — Origin-checked, deletes the session row (immediate revocation,
  no async GC), clears the cookie.

### Shared-password visibility (`password`)

A single shared password on an app, for external demos — the URL + password are handed out (e.g.
at a conference) without making the app `public`. Unlike SSO this is **entirely same-origin on the
app host** (no auth host, no handoff), so the OIDC review surface is untouched.

- **Storage (portal).** The owner manages the credential through authenticated routes —
  `POST/GET/DELETE /api/v1/apps/:slug/access/password` and `…/rotate` (`apps/portal/src/routes/apps.ts`).
  Enabling flips visibility to `password` and mints an xkcd-style passphrase
  (`correct-horse-battery-staple`, `apps/portal/src/access/`). Two representations are stored
  (`apps/portal/src/access/password.ts`): `passwordHash`/`passwordSalt` (scrypt) and `passwordEnc`
  (AES-256-GCM under `PORTAL_SECRET`, decryptable for re-display). The password **never** appears in
  `toApp`/`toManifest` or any open read.
- **Projection.** Only `passwordHash`/`passwordSalt` reach the edge (registry projection); the edge
  holds nothing decryptable.
- **Challenge (edge).** `apps/edge/src/auth/routes/passwordLogin.ts` serves `GET /_auth/login` (a
  whitelabeled form under its own strict CSP) and verifies `POST /_auth/login`: Origin-checked
  (login-CSRF), brute-force throttled (`loginThrottle.ts` — 429), and the password re-derived with
  async scrypt + `timingSafeEqual` (`password.ts`, fail-closed). On success it inserts an **active**
  session directly (`SessionStore.createActive` — no pending/redeem) and sets `__Host-session`.
- **Identity.** Each login mints a fresh pseudonym (`pw_<random>`, `displayName: "Guest"`, no
  groups), so visitors get isolated `user`-scope storage. No silent refresh for a password
  session — the session hard-expires and re-prompts. `visibilityAllows` returns `true` for a
  password session (the password was the proof); a cold navigation goes to the same-origin
  `/_auth/login` instead of the OIDC `/start`.
- **SSO is also accepted.** A `password` app is *the shared password **or** any SSO user* — the
  password is for externals; internal users just sign in. So `resolveAppForAuth` admits password
  apps into the OIDC flow (only `public` is excluded — it has no session), the callback's
  `visibilityAllows` lets any authenticated user through, and the login page links to
  `auth.<control domain>/start?app=…`. An SSO session on a password app behaves like any other (real
  identity + groups, silent refresh): the gate's refresh/visibility redirects target the auth
  host, while only the *cold* redirect picks the password form — a password session never reaches
  a refresh (its `refreshDueAt == expiresAt`).

Tests: `apps/edge/src/auth/password-login.test.ts` + `loginThrottle.test.ts`,
`apps/portal/src/routes/access-password.test.ts` + `access/password.test.ts`.

> **Throttle status (ADR-0004 / ADR-0011, issue #13).** The login/anonymous throttle is now
> backed by a **shared Postgres counter** (`rate_counters`, `gateway/counterStore.ts`): the limit
> holds across replicas (no more per-process N×), the atomic `INSERT … ON CONFLICT … RETURNING`
> makes the login throttle **reserve-first** (closing the check-then-increment TOCTOU), and one
> interval sweep in `server.ts` GCs it (the old never-scheduled `sweep()` is gone). Scrypt cost is
> at OWASP's `N=2^17` (ISSUE-08). `trustProxy` is a config knob (`EDGE_TRUST_PROXY`, default off in
> code) naming the **address** of the trusted ingress, and the deployments set it to `100.64.0.0/10`,
> so `req.ip` is the real client and the per-client limits are per-client (issue #13). That value is
> **confirmed against the live ingress** (2026-09-03), and confirming it is what found the bug: the
> earlier default named the ACA *apps* subnet, which the ingress peer is not in, so the walk
> truncated at the socket peer and every client bucketed per Envoy pod with `/health` green
> (ADR-0011's 2026-09 amendment). A hop count is no longer accepted — fastify 5.12.1 removed that form
> (GHSA-3m5p-2c4r-xxw2) because it trusts by position without checking the peer, and the edge now
> refuses to boot on one. That value belongs to a deployment's ingress topology, not to Helix —
> front the edge with a CDN or WAF and it must be re-verified there.

### Crypto + key material

- `apps/edge/src/auth/flow.ts` — the signed `__Host-oidc-flow` cookie (HS256, 10 min).
- `apps/edge/src/auth/handoff.ts` — the one-time handoff JWS.
- `apps/edge/src/auth/sessions.ts` — random cookie value, stored as SHA-256 hash; the atomic
  redeem; lookup scoped to `appId`.
- `apps/edge/src/auth/secrets.ts` — HKDF-derives separate `flowKey` + `handoffKey` from
  `EDGE_AUTH_SECRET` (≥32 bytes). Auth env vars are set together or not at all; missing them
  fails closed.

### Keeping the URL-borne token out of logs (issue #20)

Steps 2–3 put live credentials in query strings (`?code=` on the callback, `?token=` on
`/_auth/complete`), and the portal SPA's own redirect URI (`/auth/callback?code=…`) is the same
shape on the control plane. Fastify's default request serializer would write all of them into
stdout, which in Azure means 30 days of Log Analytics retention.
[`@azx-pbc/shared/logging`](../../packages/shared/src/logging.ts) replaces that serializer with one
that rewrites sensitive query values to `REDACTED` (names matched case-insensitively, after
percent-decoding, `&`/`;`/`#` all treated as separators), on every route, with the rest of the URL
byte-identical. `loggerOption()` is wired into **all four** Fastify services — edge, dev gateway,
portal, egress — so the control plane doesn't leak what the data plane redacts.

Two auth-specific consequences beyond the token itself:

- **`error_description` never reaches a log.** `AuthorizationResponseError` carries it as an own
  enumerable property, so pino's stock `err` serializer wrote IdP-chosen (and, with a valid flow
  cookie + state, attacker-chosen) free text verbatim. `summarizeExchangeError`
  (`apps/edge/src/auth/oidc.ts`) reduces an OAuth failure to its enumerated `error` code; anything
  else — IdP down, bad nonce — keeps its full `err` and stack, because that text is ours.
- **Both redirect legs** send `Cache-Control: no-store` + `Referrer-Policy: no-referrer`.

The guarantee is scoped to the `req.url` field — Fastify's own double-send messages interpolate a
raw URL, and hand-rolled log calls must pass `redactUrl` themselves. What we don't own — a Front
Door / WAF / CDN placed in front of the edge, which logs full request URIs by default — is the ops
note in [`apps/edge/README.md`](../../apps/edge/README.md#logging-and-redaction); browser history is
the residual. Tests: `packages/shared/src/logging.test.ts`, `apps/edge/src/logging.test.ts`, and the
callback-redirect + `error_description` cases in the adversarial suite.

### The adversarial suite (project plan §6)

Anything touching this path changes its tests **in lockstep**:

- `apps/edge/src/auth/adversarial.test.ts` and `handoff.test.ts` — replay, audience confusion,
  open-redirect, cookie tossing, state/nonce tampering, expired/alg-confused tokens, fixation.
- `apps/edge/src/auth/flow.integration.test.ts` and `sessions.integration.test.ts` — the real
  flow against an ephemeral dev-idp, including the concurrent-redeem race and `prompt=none`.
- Split-layout coverage (local Chromium / in-process fixtures unless noted): `routing/hosts.test.ts`
  (auth only on `auth.<control>`; `auth.<apps>` is platform); `config.test.ts` (boot validation and
  `EDGE_LEGACY_APP_REDIRECT` polarity); `routing/legacyRedirect.test.ts` (307 rules and open-redirect
  safety); `auth/validate.test.ts` and `auth/gate.test.ts` (Origin and gate redirects across
  domains); `auth/flow.integration.test.ts` (full handoff against dev-idp); `auth/adversarial.test.ts`
  (auth-host impersonation on the apps domain and cross-domain cookie scope); `routing/consentStart.test.ts`
  and `routing/connectionsProxy.test.ts` (control callback URL; `auth.<apps>` does not proxy);
  `devGateway/consentStart.test.ts` (popup URL on the control domain).

---

## Portal / CLI auth (the control plane)

**What it is.** Portal `/api/v1/...` routes — reads and mutations alike — require a bearer
token run through a **verifier chain** in `apps/portal/src/auth/verifier.ts`; the first verifier
that accepts wins. Only `/health` and the auth-config bootstrap endpoint stay public (so the SPA
can sign in). Built from env in `apps/portal/src/plugins/auth.ts` (the `authenticate`
preHandler).

1. **OIDC verifier** — an IdP-minted JWT verified statelessly over the issuer's JWKS (`jose`).
   Discovers `.well-known/openid-configuration`, enforces `https://` issuer + JWKS, asymmetric
   algs only (RS256/ES256), checks issuer/audience/exp/iat with 5 s clock tolerance. Configured
   by `PORTAL_OIDC_ISSUER` + `PORTAL_OIDC_AUDIENCE`.
2. **Dev-token verifier** — a timing-safe compare against `PORTAL_DEV_TOKEN` for CI/scripts,
   attributed to `PORTAL_DEV_ACTOR`. **Refused in production** (throws at startup).

Supporting routes: **`GET /api/v1/auth/config`** (public — issuer + client IDs for the CLI/web
to bootstrap) and **`GET /api/v1/me`** (echoes the authenticated actor `{oid?, sub, via, name?,
email?}` — the `oid` is the canonical principal id since ADR-0048, additive so older portals
omit it — powering `helix whoami`). Tested in `apps/portal/src/auth/oidc.integration.test.ts`.

**Authorization model (v0):** authz is **flat** — any authenticated portal-audience principal may
mutate ("authenticated == authorized"), the same level as the old shared token, now attributed in
the audit log. The **BOLA** (broken object-level authorization) half of that is now closed: an
`ownsApp` owner-or-admin gate guards every app-scoped mutating and secret route, fail-closed on a
null `ownerId` (ADR-0007, issue #9). What remains is per-app **RBAC** — reads are still
authenticated-only, so any authenticated principal can see any app's metadata. That is the v1 fix,
not merely a nice-to-have.

## Admin session revocation

The admin **Sessions** screen (`/admin/sessions` in the portal SPA; `apps/portal/src/routes/sessions.ts`
on the API side) lists every live app-user session and revokes them, **per user, across every app**
— the v1 control-plane feature architecture §4.2 promised, closing ADR-0004's ISSUE-11 window.

**The mechanism is the one the design already had.** Sessions are server-side precisely so
revocation is real: the edge's gate consults `session_lookup` on every request with no cache
(`gate.ts`), so `POST /api/v1/sessions/revoke` — one `DELETE FROM sessions WHERE "userOid" = …`
— kills the session for the *next* request. Navigations 302 to sign-in, `/_api/*` fetches get
401, and the browser's still-present cookie becomes a key to nothing. No edge change, no cookie
blocklist, no "revoked" flag to project. The delete also takes the user's never-redeemed pending
row (a login in flight) as collateral of the same kill.

What it closes, and what it doesn't:

- **It closes the stale-snapshot window on demand.** A user removed from an Entra group keeps
  serving on the group snapshot captured at login/refresh until the next silent refresh (≤ the
  refresh interval, hard-capped at the session TTL). Deleting the row ends it now, and re-login
  re-checks group membership at the OIDC callback — so a user who actually lost the group cannot
  get back in.
- **It revokes sessions, not principals.** A user whose entitlement still stands simply signs in
  again — correct, because sign-in re-evaluates everything fresh. Blocking a person entirely is
  Entra's job (disable the account / remove the group); denying an app is the archive (410). An
  in-flight request or stream completes; an offline app's cached shell still cold-boots, but its
  `/_api/*` calls die instantly (ADR-0035).

Routes (both `requireAdmin`, the same gate and reasoning as the gateway audit log — the rows carry
a name and address for every app user of every hosted app):

- **`GET /api/v1/sessions`** — live rows only (activated, unexpired: exactly what the gate would
  still admit), flat, with the app slug joined. Group ids in each session's snapshot are resolved
  to display names server-side through the directory `getGroups` seam (the my-groups primitive,
  under the same per-actor resolve budget); a spent budget, an unavailable directory, or a
  transient Graph failure degrades to `groupsResolved: false` + raw ids rather than failing the
  list — **revocation never depended on Graph**. `tokenHash` is never projected.
- **`POST /api/v1/sessions/revoke`** `{userOid}` — the user-level kill above. Idempotent by
  design (`{removed: 0}` on a stale click, not a 404), returns `{removed, apps}`. Every attempt
  writes a platform-level audit event (`session.revoke`, `appId` null) with the display half
  captured from the removed rows — which are about to be swept, so that is the only place the
  name survives (ADR-0021's capture-at-write).

**Grant posture** (migration `20260921120000`): `helix_portal` holds `SELECT` + `DELETE` on
`sessions` and nothing else — it cannot mint a session or rebind a `tokenHash` (i.e. steal one);
the handoff's atomic redeem stays edge-only **by grant**. `role-split.integration.test.ts` holds
that line, and `sessions.rls.integration.test.ts` proves the kill itself: a `helix_portal` DELETE
is missed by the edge's very next lookup.

## Planned / not yet built

- **Per-app RBAC** on the portal side (v1). The BOLA half is done (`ownsApp`); what's left is
  owner/editor/viewer roles and owner-scoped **reads**, which are still authenticated-only
  (ADR-0007, issue #9).

**Since shipped — per-app group visibility.** `visibility: group` is real end to end
([ADR-0040](../adr/0040-entra-group-visibility-directory-seam.md)). An app is scoped to **N
groups, any-of** (`visibilityGroupIds text[]`, capped at 10 in zod), and `visibilityAllows`
intersects that set against the session's group snapshot — checked at the OIDC callback,
re-checked per request against the live registry entry, and re-snapshotted on silent refresh.
Empty set denies, and so does an unrecognised mode: the gate fails closed.

Both Entra registrations declare `groupMembershipClaims: SecurityGroup`, so the `groups` claim
carries security-group object GUIDs — **not** an App Role per group, which would have made
scoping an app to a group an infrastructure deploy. Because Entra has no "emit display name"
option for cloud-only groups, the portal resolves names through `packages/directory`
(`searchGroups`/`getGroups` only — deliberately no member enumeration, though the grant permits
it) against one admin-consented Graph permission, `GroupMember.Read.All`, held by the portal's
managed identity. Names are resolved live and never stored beside the ids; the one exception is
an audit row, which records them as observed at write time.

Three things worth knowing before using it:

- **Membership is transitive.** Scoping to a parent group admits members of its nested children.
  The Access tab's copy says so.
- **A tenant has to be rolled out first.** Until an operator applies
  [`entra-group-claims-rollout.md`](../runbooks/entra-group-claims-rollout.md) the claim is
  empty and a `group` app denies everyone including its owner — which is why the create form
  still doesn't offer the mode (`UNAVAILABLE_AT_CREATE` in `AppCreateForm.tsx`) while the Access
  tab does.
- **The picker degrades, the gate doesn't.** Without the Graph grant the group picker reports
  itself unavailable and the Access tab falls back to entering ids directly, behind a banner
  naming the permission. Enforcement never depended on Graph.
- **Who may search is a deployment setting.** `PORTAL_DIRECTORY_SEARCH` is `everyone` (the
  default, and what ADR-0040 shipped), `admins`, or `none`. It gates
  `GET /api/v1/directory/groups` outright. `my-groups` is never gated — it resolves the claim
  on the caller's own verified token. The app-scoped resolve
  (`/apps/:slug/visibility/groups`) additionally requires owner-or-admin **once a tier is
  set**, because group ids on an app are never validated against the directory, so an
  ungated resolve is a name-and-existence oracle over ids the caller chose; it stays open
  under `everyone`, where the apps-table badge needs it and there is no posture to enforce.
  A restricted caller keeps a working picker — own groups by name, their own apps' stored
  groups by name, add-by-id — and loses only the discovery of groups they're not in.
  Distinct from the bullet above on purpose: nothing is broken, and the UI must not say it
  is (ADR-0040 decision 11).

Above roughly 200 groups Entra replaces the claim with `_claim_names`, at which point the edge
reads no groups and denies. That is fail-closed but indistinguishable from a bug, so the edge
logs it specifically; resolving overage would put a Graph call on the sign-in path in the plane
[ADR-0003](../adr/0003-dependency-minimal-edge.md) forbids one, and is deferred.

**Since shipped — real Entra registration.** Production now authenticates against a real Entra
app registration; the swap was config-only (issuer/client), exactly as designed, and the local
issuer had already exercised the flow end to end. The step-by-step setup is the
[Entra registration runbook](../runbooks/entra-app-registration.md). Two decisions are baked in
there: authorization rides **Entra App Roles** (the `roles` claim carries human-readable values
like `platform-admin` — no GUIDs, no Graph, no group-overage), and the portal audience is
`api://<guid>` rather than the dev `urn:helix:portal`.
