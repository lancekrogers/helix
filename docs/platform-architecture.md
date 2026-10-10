# AZX App Platform — Architecture Design Doc

**Status:** Draft v2 · updated July 2026 (v2: dedicated `azx.helix.azxlabs.io` domain, Git builds deferred to v2 phase, auth appendix added). Implementation is **deployed on Azure** — all three planes, the gateway, secret-backed connections, and the approval workflow run in production against real Entra OIDC and a live Key Vault. The outstanding M5 residual is a real pilot app end to end (project plan §4, §5).
**Scope:** Secure hosting for vibe-coded AI apps. Self-hosted, Azure first (we are customer #0), portable to other clouds later.

---

## 1. Summary

Helix hosts untrusted, AI-generated static frontends behind SSO by default.
Apps use platform APIs for language models, storage, and integrations. The
gateway checks identity and permissions, applies quotas, and records usage.

**Every hosted app is untrusted code.** Generated apps may contain faulty logic,
malicious dependencies, or injected instructions. Helix restricts each app's
permissions and access to other apps rather than trying to verify its code.

---

## 2. Goals and non-goals

**Goals (v1)**

- Host static frontend apps (SPA bundles) at `<app>.azx.helix.azxlabs.io` — a dedicated apps domain, deliberately separate from the corporate domain (§4.1)
- SSO by default via Microsoft Entra ID; per-app override to public or password-protected
- Deploy by uploading a built bundle (CLI or portal). Git-connected builds are deferred — see §5
- Platform API + MCP gateway giving apps governed access to LLMs, storage, and integrations
- Per-app scoped data storage so most apps need no custom backend
- Tens of apps, one org, low ops burden

**Non-goals (v1)**

- Arbitrary containers or custom backends (phase 2 at earliest)
- In-platform app builder (assume apps built elsewhere with Lovable/Cursor/Claude Code etc.)
- Multi-org tenancy (but avoid decisions that block it — see §9)

---

## 3. System overview

```
 app users ── HTTPS ──▶ *.azx.helix.azxlabs.io
                        ┌─────────────────────────────────────────────┐
                        │ helix-edge — data/policy plane (stateless)  │
                        │ host routing · sessions + OIDC handoff      │
                        │ CSP injection · asset serving from Blob     │
                        │ /_api/* gateway: LLM proxy · app data ·     │
                        │ fetch-proxy policy · quotas · metering·audit│
                        └──┬───────────┬───────────┬──────────────┬───┘
                           ▼           ▼           ▼              ▼ attested
                      Blob storage  LLM vendors  Postgres     instruction
                      (versioned   (Azure OpenAI (registry·   (signed; no
                       bundles)     Anthropic…)   app data·    secrets cross)
                                                  sessions·        │
                                                  audit)           ▼
                                          ┌──────────────────────────────────────┐
                                          │ helix-egress — mechanism plane        │
                                          │ (its own network egress zone)         │
                                          │ secret injection · SSRF controls ·    │
                                          │ outbound HTTP to third-party APIs     │
                                          └──────────────┬─────────────┬──────────┘
                                                         ▼             ▼
                                                   third-party    Key Vault /
                                                   APIs           secret store

 app owners ── HTTPS ─▶ portal.azx.helix.azxlabs.io
                        ┌─────────────────────────────────────────────┐
                        │ helix-portal — control plane (privileged)   │
                        │ portal UI + API · deploy endpoint           │
                        │ registry writes · capability approvals      │
                        │ scheduled jobs: usage rollups · audit       │
                        │ shipping · ACME cert renewal                │
                        └─────────────────────────────────────────────┘
                        portal writes Postgres + Blob; edge reads a
                        cached registry projection (§7)
```

Three deployable services use managed Postgres, Blob storage, and Key Vault:

- **Edge (data/policy plane):** handles app routing, sessions, CSP, static assets,
  and gateway authorization, quotas, and audit. It keeps a registry cache and
  holds operational auth/signing credentials, but cannot read app connection
  secrets. Production Blob access uses a read-only managed identity
  ([ADR-0027](adr/0027-blob-auth-managed-identity.md)). Rate counters are shared
  through Postgres ([ADR-0011](adr/0011-in-memory-rate-limiting.md)).
- **Portal (control plane):** manages apps, versions, approvals, secrets, and audit
  views. It is not routed through app subdomains. Scheduled infrastructure work
  runs in separate jobs.
- **Egress (mechanism plane):** verifies signed instructions from the edge,
  resolves and injects connection credentials, applies SSRF controls, and makes
  outbound requests. It has its own network zone and accepts no app-user traffic.

The process split keeps privileged administration and connection credentials out
of the service facing untrusted apps. It also lets the portal deploy without
interrupting edge streams. Egress needs a separate network policy, so it runs
separately from the start ([ADR-0001](adr/0001-three-runtime-split.md)).

Postgres enforces separate permissions ([ADR-0002](adr/0002-postgres-role-split-rls.md)):

| Role | Access |
| --- | --- |
| `helix_portal` | Control-plane DML; not the schema owner. Migrations run as `helix`. |
| `helix_edge` | Explicit grants for registry reads, metering/collection inserts, and RLS-scoped app data. No connection-secret reads or registry writes. |
| `helix_egress` | Secret reads and updates to `lastUsedAt`, under its restricted grants. |

Production requires role-specific database URLs. The portal and edge refuse to
fall back to the owner URL; local development permits that fallback. The
`role-split.integration.test.ts` suite checks the database boundaries.

**v0 consolidation option:** edge and portal can share a process if their routers
remain strictly separated by hostname. Control-plane handlers must never be
mounted on app hosts. Separate the processes before hosting public apps. Azure
already deploys them separately; deployment review enforces that separation
([ADR-0012](adr/0012-edge-portal-codeploy.md)). Egress must always run separately
to preserve its network and credential isolation.

All three containers run on Azure Container Apps for v1 (AKS if/when needed), keeping the stack portable. Egress sits in its own egress-permitted network zone; when `deployFirewall` is true, the edge and portal subnets are forced through the firewall and denied general internet egress. With the firewall off they use default internet egress while egress traffic stays governed by the application SSRF filter and the `snet-egress` NSG (see [network controls](features/network-controls.md)).

---

## 4. App hosting and identity at the edge

### 4.1 Routing and TLS

- Serve apps on a dedicated domain, such as `azx.helix.azxlabs.io`, separate from
  corporate sites. This separates branding, cookies, and browser policies.
  Entra credentials are entered only on the identity provider's domain;
  shared app passwords use the platform's distinct login form.
- Wildcard DNS routes `*.<base>` to the edge. A wildcard certificate covers app
  hosts; the deployed setup uses ACME DNS-01 renewal.
- Give each app its own subdomain and browser origin to separate DOM, storage,
  and host-only session cookies.

### 4.2 Authentication

The edge authenticates visitors. Apps do not implement login.

| Visibility | Access |
| --- | --- |
| `internal` (default) | Any authenticated directory principal, including Entra B2B guests. |
| `group` | An authenticated principal whose group snapshot matches the app's configured groups. |
| `password` | A shared app password; creates a pseudonymous session, not a verified directory identity. |
| `public` | No login; requires an owner request and platform-admin approval because gateway access remains available. |

The name `private` is reserved for future owner-plus-admin access; see TODO.md.

For OIDC, use one callback on `auth.<base>` because Entra requires exact registered
redirect URLs. After login, a short-lived, signed, single-use, audience-bound
handoff token transfers the result to the app host. Validate app and return-path
parameters to prevent open redirects. Appendix A describes the flow and required
adversarial tests.

Sessions use host-only `__Host-` cookies. Sibling subdomains are still same-site,
so additional controls are required:

- The `__Host-` prefix rejects parent-domain cookies that could shadow a session.
- Gateway Origin checks prevent cross-app requests from using another app's
  session. CSP must explicitly set `form-action 'self'`; it does not inherit
  `default-src`.
- Submit the stable apps domain to the Public Suffix List so sibling apps become
  cross-site for cookie purposes. This also prevents domain-wide cookies;
  platform services already use host-only cookies.

Silent OIDC refresh checks current group membership and account status. Removal
therefore takes effect within the session lifetime. Admin session revocation
deletes a user's sessions and takes effect on the next request. Password forms
are platform-rendered and visually distinct from Entra sign-in.

Apps can call `/_api/me` for the current user's display information. The gateway
attributes requests to the resolved caller. The implementation is the TypeScript
edge service; see [authentication](features/authentication.md).

### 4.3 Serving

Static assets live in private Blob storage at `apps/<app-id>/<version>/...`.
The edge applies the app's access gate before serving them. v1 does not place a
CDN in front of gated apps. Upload creates an immutable version; promotion changes
the registry's live-version pointer, and rollback selects an earlier version.

### 4.4 Browser-side containment (CSP)

The proxy applies Content-Security-Policy to every app response. Because the app
itself is untrusted, the policy focuses on restricting data destinations while
allowing the script patterns common in generated apps.

**Strict — data-flow directives.** Restrict connections, form submissions, and framing:

- `connect-src 'self'` — apps cannot call arbitrary third-party APIs from the browser. The gateway is same-origin at `/_api/*`, so platform capabilities need no exception. Additional origins are a declared, owner-requested, auditable capability.
- `form-action 'self'` (see §4.2 — required for cross-app CSRF protection)
- `frame-ancestors 'none'` (no embedding apps in other apps)

**Relaxed — code-provenance directives.** Allow inline scripts and common build
patterns for compatibility. This policy does not try to establish trust in app code:

- Inline scripts, inline styles, event-handler attributes, and `eval` are permitted. A single-file Claude-generated HTML app deploys and runs untouched.
- A curated CDN allowlist includes cdnjs, jsdelivr, unpkg, esm.sh, Google Fonts,
  and Tailwind CDN. These can serve third-party code; the policy does not establish
  trust in that code.

- `img-src https: data: blob:` allows remote images. Image requests and
  navigation can transmit data, so CSP does not prevent all exfiltration.
- `wasm-unsafe-eval` and `worker-src 'self' blob:` allow WebAssembly and ordinary
  workers. Service workers cannot register from blob URLs. The edge rejects
  app-supplied service-worker registration requests because a root-scoped worker
  could intercept the handoff URL at `/_auth/complete` (Appendix A.3).

  The offline capability ([ADR-0035](adr/0035-offline-capability-platform-service-worker.md))
  provides a platform-authored worker limited to an approved non-root scope.
  Root and `_` namespaces are forbidden, keeping `/_auth/*` and `/_api/*` outside
  its scope. The edge injects registration and serves a self-unregistering
  tombstone after revocation. The capability supports offline startup; ordinary
  page JavaScript remains responsible for its own durable state and asset caching.

**CSP feedback.** Help app authors identify blocked requests and request access:

- `report-to` points violation reports at the platform. The portal turns them into plain-English, actionable messages: "Your app tried to call `api.weather.com` and was blocked — request this origin?" One click files the capability request. Silent breakage becomes a guided fix.
- Deploy-time linting still runs, but as a courtesy warning ("your app references `api.example.com`; it will be blocked until granted"), not a gate.
- The gateway's fetch-proxy (§6.1) gives blocked third-party calls an on-platform answer — route through `/_api/fetch` and get auditing, metering, and server-side secrets instead of a CSP exception.

CSP does not prevent all data exfiltration. Navigation, HTTPS images, LLM prompts,
and approved external origins remain possible channels; see §10.

---

## 5. Deploy (v1: upload only)

v1 has exactly one path into the platform: **upload of a pre-built bundle** (zip of `dist/`) via CLI or portal. The deploy endpoint (part of the control plane) validates the artifact (static files only, size/type sanity checks), runs the CSP courtesy lint (§4.4), stores it as an immutable version in Blob, and updates the registry pointer.

**Git-connected builds are out of scope for v1.** Running `npm install` and build
scripts means executing untrusted code. Hosted builds need ephemeral workers,
credential isolation, and outbound network controls. Authors can build locally
or in their own CI and upload the output. A future hosted-build service would use:

- Ephemeral container per build, destroyed after; no platform credentials inside — artifacts leave via a one-way, scoped upload token
- Egress allowlisted to package registries, acknowledging it's leaky (git deps, tarball URLs, postinstall scripts) — the credential-free environment is the real defense
- Build output enters the same upload pipeline as manual deploys, so validation and CSP linting are shared

Until then, a thin CLI (`helix deploy`) keeps the workflow one command, and teams who want CI can run the CLI from their own GitHub Actions — Git-based workflow, zero platform build infrastructure.

### 5.1 Agent-driven deploys (the deploy skill)

Most app authors work inside coding agents (Claude Code, Cursor, etc.), so the deploy path should meet the agent where it is. On app creation, the portal offers a downloadable **deploy skill** — an agent-agnostic bundle of prompts + scripts that teaches any agent the deploy API: push a bundle, check status, list versions, roll back.

**The skill contains no credentials.** It may be committed, shared, or retained
in agent transcripts. A deploy credential would let its holder publish code with
the app's permissions, so authentication must happen separately:

- First deploy triggers an **Entra device-code flow**; the script caches a short-lived, per-user × per-app, deploy-scoped token in the OS keychain — outside the repo, outside agent context. Subsequent deploys refresh silently.
- Attribution and revocation come free: every deploy is audited as (user, app), and a departing user's deploy access dies with their Entra account.
- Deploy tokens are deploy-plane only — they can never call gateway APIs or read app data.
- If headless use cases later demand static tokens (expect this argument), they must be deploy-only, expiring, shown once, and prefixed (`azxd_...`) so secret scanners catch them, with anomaly alerts on use from new IPs. Default stance: don't.

**Preview-then-promote guardrail.** Agent instructions can be influenced by
untrusted repositories and dependency docs. Deploys therefore create previews
by default, with a separate human promotion step before users receive the new
version. A trusted solo workflow can opt out.

---

## 6. The API/MCP gateway (the value add)

Apps get capabilities by calling the platform gateway — same-origin path `/_api/*` on the app's own subdomain, proxied by the edge (avoids CORS entirely and keeps the session cookie usable).

### 6.1 Service catalog

- **LLM inference:** chat/completions/embeddings proxied to Azure OpenAI / Anthropic etc. Platform holds the vendor keys; apps never see them. Per-app model allowlists, token budgets, and rate limits. Quota enforcement: in-flight requests (including streams) run to completion; new requests are blocked once the budget is hit — no mid-stream cutoffs. The vendor key is a `platform`-scoped connection secret resolved by `helix-egress`, not held by the edge: the edge keeps all the policy (allowlist, budget, metering, SSE relay) and mints an `llm` attested instruction, and egress injects the key and streams the response back — the same policy/mechanism split as the fetch-proxy (see `docs/design/secrets-and-connections.md`). The edge holds no vendor key in any environment: when egress is unconfigured the LLM capability fails **closed** (503) — there is no direct edge→Anthropic path ([ADR-0008](adr/0008-llm-key-via-egress.md), issue #10).
- **App data (shipped):** KV/document storage at `/_api/data/...` in **three scopes** — per-user (RLS-partitioned by the authenticated user, so apps cannot read one user's data on behalf of another), app-`shared`, and write-only `collections` (the app appends but cannot read or enumerate; the owner drains them through the portal export API — a contact-form pattern where the app must not be able to harvest its own submissions). Backed by Postgres (JSONB) internally. This is what removes the need for custom backends: most vibe-coded apps need "save my stuff" and nothing more. Design: `docs/design/app-data-storage.md`.
- **File storage:** scoped blob upload/download for user files.
- **Fetch-proxy (shipped, M4.5):** governed outbound HTTP at `/_api/fetch/<url>` for third-party APIs, so a blocked `connect-src` call has an on-platform answer — audited, metered, with secrets injected server-side where configured. The edge enforces the *policy* (identity, authz, quota, audit) and hands a signed attested instruction to **`helix-egress`**, which performs the call under SSRF hardening: isolated egress zone, private/link-local ranges blocked, no redirect-follow, per-app origin allowlist. An **opt-in transparent shim** (`capabilities.fetch.shim`) goes further: the edge injects a one-line script into the app's HTML at serve time that monkeypatches `fetch`/`XMLHttpRequest`, so a vibe-coded `fetch('https://api.github.com/…')` routes through the proxy **unedited**. Design: `docs/design/fetch-proxy.md`.
- **MCP passthrough (v1.x):** platform-registered MCP servers (internal tools, SaaS connectors) exposed to apps as governed endpoints — **wrapped as REST**, since plain HTTP is what vibe-coded frontends can actually call. Apps speaking MCP directly to the gateway is deferred until demand materializes. The app declares which MCP servers it needs; the gateway enforces the grant.
- **Secret-backed connections (shipped, M4.5):** when an app needs a third-party API requiring a secret, the secret lives in the platform (Key Vault in prod; an envelope-encrypted store in dev) and is read only by `helix-egress`, which injects credentials server-side on the outbound hop. Secrets never reach the browser, and never the edge (`helix_edge` has no grant on the secrets table). Design: `docs/design/secrets-and-connections.md`.

### 6.2 Request identity

Every gateway request carries two identities:

- **User:** from the edge session (who is clicking) — a verified Entra identity for internal/group apps; a pseudonymous session identity for password/public apps
- **App:** from the app's registered ID bound to its subdomain (which code is calling)

Authorization checks the app, user, and requested capability together. An app
can use only its granted capabilities, and each call is attributed to its caller.

### 6.3 Capabilities model

Each app has a manifest (editable in the portal, versioned):

```yaml
app: cost-explorer
visibility: internal           # internal | group | password | public
capabilities:
  llm: { models: [claude-fable-5, claude-opus-4-8], dollarsPerDay: 50 }
  data: { user: true, shared: true, collections: [contact] }
  fetch: { shim: true, origins: [{ origin: https://api.github.com, connection: github }] }
  mcp: []                      # MCP servers (REST-wrapped, v1.x)
  externalOrigins: []          # extra CSP connect-src/img-src origins
```
(Illustrative; the authoritative zod schema is `packages/shared/src/manifest.ts`.)

Grants above the baseline require platform-admin approval.
`classifyChange` in `packages/shared/src/approval.ts` separates baseline changes
from elevated requests, such as non-curated models, larger budgets, new proxied
origins, MCP servers, or public visibility. Baseline changes apply immediately;
elevated changes enter an `ApprovalRequest`. Only approved settings reach the
`apps` row and the edge. The append-only `gateway_calls` ledger records app,
user, capability, outcome, and cost. See `docs/design/approvals.md`.

### 6.4 Public apps

Public apps can use granted gateway capabilities with tighter default quotas
and per-IP abuse limits. They have no user-scoped storage or pseudonymous cookie
identity. This stateless anonymous model remains the default until a concrete
use case requires otherwise. Public visibility requires admin approval.

---

## 7. Control plane (`helix-portal`)

Portal + REST API:

- **App registry:** create app, subdomain, visibility, manifest, deploy history, rollback
- **RBAC:** platform admins approve elevated grants (built — §6.3). App owners/editors/viewers mapped to Entra users and groups is a v1 item, not yet enforced. Note ([ADR-0007](adr/0007-portal-authz-v0.md)) that the v0 posture was **authenticated == authorized**; the BOLA half is now closed by an `ownsApp` owner-or-admin gate on every app-scoped mutating route (issue #9). What is still absent is per-app RBAC: reads remain authenticated-only, so any authenticated principal can still *see* any app's metadata
- **Observability:** per-app usage (requests, LLM tokens, storage), gateway audit log search, deploy logs
- **Lifecycle:** archive/disable apps — proxy returns 410 with `Clear-Site-Data`, capabilities revoked immediately at the gateway (a cached service worker can keep serving the UI, but its API calls die instantly). Retired subdomains are quarantined, not reused, to avoid stale cookies/service workers leaking to a new occupant

The registry is the source of truth (Postgres). The edge proxy and gateway read a cached projection of it (refresh on change, sub-second), so the data path doesn't depend on the portal being up.

---

## 8. Azure mapping (v1)

- **Compute:** Azure Container Apps: edge, portal, and egress, plus scheduled jobs and an optional dev-gateway. Hosted builders remain deferred.
- **Assets/files:** Blob Storage
- **Registry + app data:** Azure Database for PostgreSQL (flexible server)
- **Secrets:** Key Vault (platform vendor keys, app connection secrets)
- **Identity:** Entra ID (OIDC); platform itself uses managed identities between components
- **LLM:** Azure OpenAI + Anthropic API as first providers behind the LLM service
- **Logs/metrics:** Azure Monitor for ops; audit log in Postgres (it's product data, not just telemetry)

Portability rule: **Azure services may appear only behind internal interfaces** (object store, SQL, secrets, OIDC). The data-path components are plain containers + Postgres + S3-compatible-able storage, so an AWS/GCP port is config + Terraform, not a rewrite.

---

## 9. Decisions and trade-offs

| # | Decision | Alternative | Why |
|---|----------|-------------|-----|
| 1 | Static-only apps in v1 | Containers per app | Removes server-side untrusted code entirely; gateway becomes the only dynamic surface. Cuts isolation work (no per-app sandboxes, network policy, runtime patching) by an order of magnitude. |
| 2 | Subdomain per app, host-only cookies | Path-based routing (`azx.helix.azxlabs.io/<app>`) | Path routing puts all apps in one origin — any XSS or malicious app reads every other app's storage and session. Non-negotiable. |
| 3 | Auth at the edge proxy | Per-app auth SDKs | Apps are vibe-coded; assume auth code in them is wrong. Centralizing makes SSO-by-default actually default. |
| 4 | Same-origin `/_api/*` gateway path | Separate `api.azx.helix.azxlabs.io` origin | No CORS, no token-in-JS handoff; session cookie just works. Slightly more proxy complexity. |
| 5 | CSP strict on data flow (`connect-src`), relaxed on code provenance (inline/eval/CDNs) | Uniformly strict CSP | Allowing inline scripts supports single-file generated apps; the policy does not establish trust in app code. Containment lives at the data-flow boundary, where violations become a click-to-request flow instead of silent breakage. |
| 6 | Self-hosted proxy/auth, not Front Door | Azure-native edge | Other customers must run this on their clouds; the edge is core IP, not infra to outsource. |
| 7 | Postgres-backed KV for app data | Cosmos DB | Portability and operational familiarity; Cosmos is Azure-only and overkill at this scale. |
| 8 | One org, but app-id partitioning everywhere | Multi-tenant now | Every row/blob/audit record keyed by app ID from day one; adding an org ID above it later is additive, not a migration. |
| 9 | Dedicated apps domain (`azx.helix.azxlabs.io`) | Subdomain of corporate domain (`apps.azx.io`) | Reputation and security isolation from the main brand (§4.1): an ugly or compromised app can't taint `azx.io`, and app-domain cookies/policies are fully separated from corporate properties. Cost: one more domain to own and explain. |
| 10 | Upload-only deploys in v1 | Git-connect + hosted builds | Hosted builds = operating a CI system + sandboxing arbitrary code execution; high effort, blocks nothing. `helix deploy` from the user's own CI gives a Git workflow without platform build infra. Revisit at v2. |
| 11 | No per-app vanity domains; the *base* domain is a per-deployment parameter | Per-app domains (`tool.example.com`) | **Per-app vanity domains stay rejected** — one app reachable at two origins reintroduces origin ambiguity and breaks wildcard-cert simplicity. But the base domain is **not** hardwired: it is a deploy-time parameter (`EDGE_BASE_DOMAIN`), so each deployment serves apps at `<app>.<base>` — our reference deployment at `<app>.azx.helix.azxlabs.io`, a customer-cloud install at `<app>.helix.<customer-domain>`. One canonical origin per app whatever the base. This is the parameterization ADR-0028 makes explicit: "custom domains" as a *feature* still doesn't exist; there is only *this deployment's* domain. |
| 12 | Three containers: `helix-edge` + `helix-portal` + `helix-egress` | One monolith, or 4+ services | Split follows the trust boundary: untrusted-facing data plane runs unprivileged and rarely restarts; privileged control plane iterates fast without killing in-flight LLM streams; the egress mechanism plane isolates the two things dangerous to co-locate with a public-facing process — plaintext secrets and outbound network — in its own network zone. One process = shared fate and blast radius; a *generic* gateway split would be internal hops for nothing, but egress earns its split with a genuinely different posture (§3). Edge/portal may still ship as one binary in v0; egress is its own container from day one. |

---

## 10. Threat model (abridged)

| Threat | Mitigation |
|--------|-----------|
| Malicious/compromised app code exfiltrates data | CSP `connect-src 'self'` raises the bar (navigation-based exfil, open `img-src`, and granted channels remain — see residual risk); capability grants are explicit and audited; violation reports surface attempts |
| App steals or rides another app's session/data | Per-subdomain origins; `__Host-` host-only cookies (theft + tossing); Origin validation at gateway + `form-action 'self'` (CSRF riding); PSL listing; gateway scopes data by app ID |
| App abuses LLM budget / runs up cost | Per-app quotas, metering, kill switch (disable app) |
| Supply-chain attack in app dependencies | v1: builds happen on the author's machine/CI, so the platform never executes them; uploaded output is static and can only run client-side under CSP. When hosted builds land: ephemeral credential-free builders (primary), registry egress allowlist (leaky, secondary) |
| Public app abused by internet traffic | Admin approval to go public, anonymous-tier quotas, per-IP limits |
| Hijacked coding agent ships malicious code (prompt injection) | No credentials in the deploy skill (device-code auth, keychain-cached short-lived tokens); agent deploys land on preview by default, human promotes to live (§5.1) |
| Phishing within SSO (app mimics login) | Entra login only ever happens on the Entra domain (password-gate forms are platform-rendered with distinct branding — §4.2); dedicated apps domain gives users a clean rule — credentials never get typed on `azx.helix.azxlabs.io`; consider a platform-standard header bar on hosted apps |
| Platform compromise (gateway holds vendor keys) | Keys in Key Vault, managed identities, least-privilege between components (the Postgres role split, §3, is the in-DB layer of this); `gateway_calls` is append-only by DB grant for every runtime role (ADR-0021), so neither the edge's nor the portal's DB credentials can rewrite history — external sealing to a write-only sink was considered and descoped (unratified demand; ADR-0021, 2026-09-17) |

A granted capability can still be misused within its permissions. For example,
an app with billing access can misrepresent the results to its users. Capability
controls limit access; they cannot guarantee correct app behavior.

---

## 11. Open questions

1. **When does phase 2 (serverless functions) trigger?** Proposed criterion: the third real app that can't ship on static + gateway APIs. Until then, resist.

Resolved since draft v1 (decisions folded into the sections above): MCP is exposed as REST wrappers, not direct MCP (§6.1); LLM quota enforcement lets in-flight requests finish and blocks subsequent ones (§6.1); public apps are fully stateless — no pseudonymous user identity unless concrete use cases demand it (§6.4); per-app **vanity** domains are rejected, but the base domain is a **per-deployment parameter** (§9 decision 11; ADR-0028 — single-tenant, customer-deployed).

---

## 12. Phasing sketch

Status as of July 2026 — the platform is **deployed on Azure**; what remains of M5 is a pilot app, not infrastructure (project plan §4, §5):

- **v0 (done):** proxy + OIDC (incl. central-callback handoff, `__Host-` cookies, baseline CSP — the isolation model ships day one, not retrofitted), upload deploys, blob serving, app registry, LLM proxy with quotas. Now runs against **real Entra**, not the local OIDC issuer; `apps/dev-idp` is a development convenience, never deployed.
- **v1 (mostly done):** `helix deploy` CLI ✅, app data API ✅, capabilities manifest + **enforced** approvals ✅, audit/usage UI ✅, password/public modes ✅, CSP violation reporting with click-to-request origins ✅ (§4.4), the agent deploy **skill bundle** (`packages/deploy-skill`) ✅, admin per-user **session revocation** ✅ (the portal Sessions screen).
- **M4.5 (done):** the `helix-egress` mechanism plane + the fetch-proxy (incl. the transparent shim) and secret-backed connections built on it (§3, §6.1). Egress ships as its own container from day one (the policy/mechanism split is physical, not deferred).
- **M5 (deployed):** Azure IaC ✅, the three planes on Container Apps ✅, real Entra (single-tenant; authz via App Roles — see the [Entra runbook](runbooks/entra-app-registration.md)) ✅, prod Key Vault verified against a live vault ✅, wildcard cert on the apps domain ✅ (automated via a scheduled certbot DNS-01 job). _Outstanding:_ one real pilot app end to end, and confirming the operator-optional egress firewall is on (project plan §4 residuals).
- **v1.x:** MCP passthrough (REST-wrapped), richer usage dashboards (latency/error dimensions).
- **v2 candidates:** Git-connect + sandboxed build service, per-app serverless functions, multi-org tenancy, app builder.

---

## Appendix A: The auth flow in detail

This expands §4.2. The actors: the browser; the edge proxy answering on the app's host (`appA.azx.helix.azxlabs.io`); the auth service (`auth.azx.helix.azxlabs.io`); and Entra ID. The proxy and auth service are the same deployment answering on different hostnames — the separation is logical, not physical.

### A.1 The login sequence

1. Browser requests `appA.azx.helix.azxlabs.io/page`. No `__Host-session` cookie → the proxy 302s to the auth service.
2. Browser hits `auth.azx.helix.azxlabs.io/start?app=appA&rd=/page`. The auth service validates both parameters against the app registry — `rd` validation is what prevents the flow being abused as an open redirector.
3. Auth service 302s to Entra's authorize endpoint with `state`, PKCE challenge, and `nonce`.
4. User signs in at Entra (SSO, MFA, conditional access — all Entra policy, none of it ours).
5. Entra redirects back with an authorization code to the **single registered callback**, `auth.azx.helix.azxlabs.io/callback`.
6. Auth service exchanges the code for an ID token over the back channel, validates signature and nonce, and checks the app's visibility rule (e.g. Entra group membership).
7. Auth service mints a **handoff token** and 302s the browser to `appA.azx.helix.azxlabs.io/_auth/complete?token=...`.
8. The proxy (now answering on appA's host) verifies the handoff token, burns it, mints the `__Host-session` cookie, and 302s to the original `/page`.
9. All subsequent requests — assets and `/_api/*` — carry the session cookie.

### A.2 Why the central callback exists

Entra requires every redirect URI to be registered exactly; no wildcards. Per-app callbacks would mean an Entra registry write on every app creation — slow, racy, and capped (Entra limits URIs per registration). So Entra knows exactly one callback. The cost: authentication completes on the wrong host, since `auth.azx.helix.azxlabs.io` cannot set a host-only cookie for a sibling subdomain. The handoff token exists purely to move the authenticated state across that gap.

### A.3 The handoff token

A bearer credential meaning "this user, authenticated, destined for appA" that travels through the browser in a URL — so it can leak via history, logs, or referrers. The token has four protections:

- **~30-second TTL** — limits the leak window
- **Single-use** (the proxy records and rejects replays) — rejects replay
- **Audience-bound to the target app** — a token captured by a malicious app is worthless on any other subdomain
- **Signed by the auth service** — nobody else can mint one

Audience binding does not protect the token from *the target app itself*: a service worker registered by the app would see the `/_auth/complete` request URL — token included — before the edge does, and could exfiltrate it for a headless redemption. That is why app-supplied service-worker registration is blocked at the edge (§4.4); the residual risk of URL transport is then bounded by the TTL + single-use properties above.

The offline capability ([ADR-0035](adr/0035-offline-capability-platform-service-worker.md))
uses a platform worker confined to a non-root scope, so it cannot intercept
`/_auth/*`. An HttpOnly nonce cookie would not provide that protection: a
same-origin worker could redeem the token with `credentials: 'include'` without
reading the cookie. Scope restriction prevents the interception.

This is the most security-sensitive code path in the platform: every guarantee depends on a small amount of code getting state validation, token burning, and audience checks exactly right. It gets a dedicated design review and adversarial tests.

### A.4 The session

After redemption, the proxy holds a server-side session record (user object ID, display name, group snapshot, app ID, expiry) keyed by an opaque ID in the `__Host-session` cookie. Server-side rather than a self-contained JWT so that revocation is real — killing a session or disabling an app takes effect on the next request, with no signed blob remaining valid until expiry. The cookie is `HttpOnly` (app JS can never read it), `Secure`, and `SameSite=Lax`.

### A.5 Authorization and refresh

Authentication establishes *who you are* once; *whether you may see this app* is checked at session creation and at every refresh. Sessions are short (hours). Refresh runs a silent OIDC re-auth (`prompt=none`) against Entra — invisible to the user, but it re-evaluates group membership, account status, and conditional access. Removing a user from an app's Entra group therefore takes effect within the session TTL, with Entra remaining the single source of truth.

### A.6 What the app sees

Apps implement no authentication code. They can call `/_api/me` to display the
current user. Changing the platform's identity provider requires no app changes.

The response is `{user: {id, displayName, email}}`. `id` is the canonical principal
id: Entra's `oid` by default, stable across app registrations in the tenant
(ADR-0048). Use it to key user data. `email` is nullable because password guests
and some issuer profiles have no address claim. It is a display field, not a
join key or delivery target. Sending it outside the app still requires a permitted
CSP destination or fetch connection. Group ids are omitted; access checks belong
to the edge, not to app code.