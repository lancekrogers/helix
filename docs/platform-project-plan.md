# AZX App Platform — Project Plan

**Status:** Draft v1 · June 2026
**Companion to:** `platform-architecture.md` (the *what and why*; this doc is the *with what and in what order*)
**How to use:** Use milestones to scope implementation work. Keep detailed designs
in `docs/design/` and update status here as work ships.

---

## 1. Tech stack (decided)

- **TypeScript everywhere, Node LTS.** One language across edge, portal, frontend, CLI, and deploy skill. A shared language makes security-sensitive code easier to review.
- **`helix-edge`:** Fastify + `undici` (streaming proxy, asset serving), `openid-client` + `jose` (OIDC, handoff tokens), `pg` with hand-written SQL (sessions, registry projection). **Hard rule: dependency-minimal.** Every npm package in the edge is code inside the trusted path; the libraries named here are roughly the whole list. No ORM. Never block the event loop — pipe streams, never buffer LLM responses.
- **`helix-portal` API:** Fastify + Prisma. The portal owns the Postgres schema and all migrations (`prisma migrate`); the edge only reads. The API is a deliberate, versioned REST surface with zod-validated request/response schemas — the portal SPA, the `helix` CLI, and coding agents are all consumers, so no tRPC/framework-coupled endpoints.
- **Portal frontend:** Vite + React SPA, TanStack Query for server state, React Router. Served statically by the portal container. No SSR/meta-framework — internal authenticated tool, nothing to gain.
- **Shared contract:** zod schemas in a shared package (app manifest, registry types, API request/response shapes). Runtime validation at every boundary; inferred types everywhere.
- **Testing:** Vitest throughout; Playwright for portal e2e when the UI warrants it.
- **Tooling:** pnpm workspaces monorepo; VS Code dev container.

## 2. Monorepo layout

```
helix/
  apps/
    edge/            # helix-edge data/policy plane
    portal/          # helix-portal API
    portal-web/      # Vite + React SPA
    egress/          # helix-egress mechanism plane (outbound HTTP, secret injection, SSRF)
  packages/
    shared/          # zod schemas: manifest, registry, API contracts
    secret-store/    # SecretStore seam: dev envelope / prod Key Vault (portal + egress)
    cli/             # helix CLI (npm-distributed; `helix deploy` etc.)
    deploy-skill/    # agent skill bundle: SKILL.md + its renderer
  examples/          # reference apps to `helix deploy`; built dist/ is committed
  infra/             # IaC for Azure (minimal at first)
  .devcontainer/
```

## 3. Local-first Azure strategy

Every Azure dependency must work in three modes: **local dev**, **integration test against real Azure**, and **production**. Two patterns depending on whether an emulator exists:

| Dependency | Local | Real | Approach |
|------------|-------|------|----------|
| Blob Storage | **Azurite** (official emulator, same SDK) | Blob Storage | Same Azure SDK both ways; thin `BlobStore` wrapper for testability |
| Postgres | Docker container | Azure Database for PostgreSQL | Same engine; no abstraction needed |
| Key Vault | `SecretStore` interface → env/file impl | Key Vault impl | No emulator exists; interface + dual implementation |
| Entra ID | Local OIDC issuer (`oidc-provider` npm) | Real Entra app registration (single-tenant; authz via **App Roles** → the `roles` claim) — see the [Entra runbook](runbooks/entra-app-registration.md) | OIDC is a standard, and the edge speaks standard OIDC — but the canonical principal id is one claim (ADR-0048, as amended): Entra's `oid` by default, `EDGE/PORTAL_OIDC_PRINCIPAL_CLAIM` for issuers whose stable id is their own `sub` (Keycloak, Okta, dex, Google), so IdP-agnostic customers remain a config path, not a rewrite |
| LLM APIs | `LlmProvider` interface → fake/echo provider | Azure OpenAI / Anthropic impls | Interface + dual implementation; fake provider streams canned tokens for testing quota/stream handling |

Config selects implementations per environment. CI runs against local/emulated; a separate integration suite runs against a real Azure dev resource group.

**Local wildcard subdomains:** use `*.local.helix.azxlabs.io` (resolves to 127.0.0.1) so subdomain-per-app routing and host-keyed routers work locally, with mkcert for a local wildcard cert — required because `__Host-` cookies demand `Secure`, and the whole isolation model must be exercisable in dev, not just in Azure.

## 4. v0 milestones (in order)

Goal: one pilot app, end to end, on Azure. Definition of done is §12 v0 in the architecture doc. v0 may ship both modules as a single binary/container if that's faster — but with two routers strictly keyed by hostname from day one (architecture §3, decision 12).

**Status at a glance (July 2026).** Helix runs on Azure Container Apps with Entra
OIDC, wildcard TLS, and Key Vault. The infrastructure is deployed; the remaining
M5 exit criteria are listed below. Milestone numbers and section anchors remain
stable because code and other docs reference them.

| Milestone | Status |
|---|---|
| **M0** Skeleton | ✅ Done |
| **M1** Registry + deploys | ✅ Done |
| **M2** Edge serving | ✅ Done |
| **M3** Auth | ✅ Done · real Entra registration is **live** (the "config-only tail" is closed) |
| **M4** Gateway v0 (LLM, then app-data) | ✅ Done |
| **M4.5** Egress: fetch-proxy + connections | ✅ Done |
| **M5** Azure + pilot | ✅ Deployed · ⏳ residuals below |

**M5 residuals.** The infrastructure milestone is met; two of its stated exit criteria are not yet:

- **A real vibe-coded pilot app end to end** (`helix deploy` → SSO login → app calls the LLM gateway) — the original §12 v0 definition of done. This will validate the complete user workflow beyond automated tests.
- **Confirm the egress firewall (`deployFirewall`) is on in the live deployments.** It defaults `true`, but it is operator-optional for cost reasons and turning it off silently removes what ADR [0005](adr/0005-ssrf-egress-controls.md) names the **primary** SSRF control, leaving the app-level `ssrf.ts` denylist — explicitly defense-in-depth — carrying the whole outbound posture. This is a check, not an assumption, precisely because the failure is invisible from inside the app.

Much of the **v1 backlog (§5)** was also pulled forward against the local stack — see that section for item-by-item status.

### M0 — Skeleton ✅ Done
Monorepo scaffold (pnpm workspaces), dev container, lint/format/test wiring, `packages/shared` with first zod schemas (app, version, manifest), empty Fastify apps for edge and portal that boot and health-check. Docker compose for Postgres + Azurite.

### M1 — Registry + deploys (control plane core) ✅ Done
Postgres schema via Prisma (apps, versions, audit), portal API: create app, upload bundle (zip validation, static-files-only check, store to Blob via Azurite), version pointer + rollback. Minimal `helix` CLI: `helix deploy`. No UI yet — API + CLI only.

### M2 — Edge serving ✅ Done
Host routing on `*.local.helix.azxlabs.io`, registry projection (cached read from Postgres, refresh on change), asset streaming from Blob, version pointer resolution, 404/410 + `Clear-Site-Data` on archived apps. Baseline CSP header injection (the §4.4 policy, statically configured). No auth yet — a dev-only bypass flag.

### M3 — Auth (the careful one) ✅ Done (local) · ⏳ Entra tail
The §4.2 / Appendix A flow: central callback on the auth host, OIDC against local `oidc-provider`, one-time handoff token (signed, 30 s, single-use, audience-bound), `__Host-session` cookies, server-side sessions in Postgres, `/_api/me`, group-based visibility checks, silent refresh. **This milestone gets adversarial tests** (replay, audience confusion, open-redirect attempts, cookie tossing) **and a dedicated review pass before anything builds on it.** Then: real Entra app registration in the dev tenant, verify the same flow against reality.

> **Implementation notes (local half, June 2026).** The local IdP is `apps/dev-idp`, run inside the workspace container (`pnpm dev:idp`) rather than as a compose service — an OIDC issuer is one string enforced by every client, and only `localhost:3002` + port forwarding reads identically from the host browser and in-container back-channels. The edge terminates TLS in dev (mkcert, §3) so `__Host-` cookies are real locally. Scope grew deliberately: the **portal API** moved off the dev-token stub onto stateless bearer-JWT verification (issuer JWKS, fixed audience — cookie sessions are the *edge* mechanism, not the portal's; the Entra swap is env-only), and the **CLI** gained `helix login`/`logout`/`whoami` via the OIDC device flow with an XDG token cache. `PORTAL_DEV_TOKEN` survives as a demoted CI fallback, refused in production. The Entra verification tail remains open.

### M4 — Gateway v0: LLM proxy ✅ Done (local)
`/_api/llm/*` on the edge: streaming proxy via the `LlmProvider` interface, per-app model allowlist, token budgets with finish-in-flight/block-new semantics, metering + audit records per call. Origin validation on `/_api/*` (CSRF — §4.2). Test quota edge cases against the fake provider; verify streaming against a real vendor.

### M4.5 — Egress mechanism plane: fetch-proxy + secret-backed connections ✅ Done (local)
The `helix-egress` service (`apps/egress`, DB role `helix_egress`) as its own deployable unit from day one — **not** built in-edge and extracted later (architecture §3). The edge stays the policy plane (identity, authz, quota, audit) and hands a signed attested instruction to egress, which resolves connection secrets, injects credentials server-side, enforces SSRF controls, and makes the outbound call. Ships with: `/_api/fetch/<url>` on the edge; the **opt-in transparent fetch/XHR shim** injected at serve time (`capabilities.fetch.shim`, so unedited `fetch()`/`axios` calls route through the proxy — originally served from `/_helix/fetch-shim.js`, inlined into the document since ADR-0035); the `SecretStore` seam (`packages/secret-store` — dev envelope / prod Key Vault); secret CRUD + the manifest `connection` binding through the approval write-gate; the app-scoped Secrets card and the global-admin Secrets page; the `helix_edge`-can't-read-`material` role-split assertion; and the adversarial SSRF suite (DNS-rebind, redirect-to-IMDS, header smuggling). The prod Key Vault impl landed here too (pulled forward — ADR-0031 made it a hard prerequisite), and is verified against a live vault in the deployment rather than only against test fakes. Designs: `docs/design/fetch-proxy.md`, `docs/design/secrets-and-connections.md`.

### M5 — Azure + pilot ✅ Deployed (pilot outstanding)
Minimal IaC: resource group, ACA apps (edge, portal, **egress in its own egress-permitted network zone**; edge/portal with no outbound internet route when `deployFirewall` is true — with the firewall off they have default internet egress while data-plane privacy and egress-side controls hold either way), Postgres flexible server, Blob, Key Vault, Entra app registration ([runbook](runbooks/entra-app-registration.md) — three registrations, single `platform-admin` app role), wildcard DNS + cert on the apps domain. Deploy a real vibe-coded pilot app end to end: `helix deploy` → SSO login → app calls LLM through the gateway.

**Landed:** the IaC is real and applied (`infra/azure`, Bicep) — the three planes on Container Apps across two ACA environments, private-endpoint-only Postgres/Blob/Key Vault, the least-privilege managed-identity matrix, real Entra OIDC replacing `dev-idp`, and automated wildcard TLS via a scheduled certbot job (DNS-01). Key Vault custody is verified against a live vault. Beyond the original scope: platform secrets by direct injection rather than ACA Key Vault references (ADR [0029](adr/0029-platform-secret-delivery.md)), images from public GHCR rather than a private ACR, an ACA job that applies migrations, the opt-in dev-gateway, and operator flags for public/password app hosting.

**Outstanding:** an end-to-end pilot app and confirmation that `deployFirewall`
is enabled in live deployments (see §4).

## 5. v1 backlog (rough order, re-plan after v0)

Most of this was pulled forward against the local stack — M4/M5 (Azure deploy) buy little before there's a product people want to host, so v1 features came first. Status as of June 2026:

1. **Portal SPA — done.** `apps/portal-web` uses React, Mantine, TanStack Query,
   and the portal API for app management, versions, capabilities, usage, approvals,
   violations, secrets, and audit. The remaining PreviewBadge marks planned
   owner/editor/viewer roles. See `docs/features/portal-web.md`.

2. **Capabilities manifest and approvals — done.** The gateway enforces effective
   per-app grants. `classifyChange` separates baseline changes, applied immediately,
   from elevated requests stored in `ApprovalRequest`. Admin decisions support
   approve, deny, needs_changes, and withdrawal. Approval checks conflicts,
   separation of duty, and idempotency before applying a change. The edge sees
   only effective settings. `requireAdmin` uses the configured admin group;
   self-approval is a development-only escape hatch. See `docs/design/approvals.md`.

3. **App data API — done.** Three scopes: per-user data under RLS, append-only
   collections with owner export, and shared keys with separate read/write grants.
   The edge has restricted database permissions. See `docs/features/app-data-gateway.md`.

4. **CSP feedback — done.** Uploads return lint warnings; the edge records browser
   violation reports through an INSERT-only grant. Approved externalOrigins extend
   each app's CSP. The portal Violations page can request an origin grant through
   the approval workflow. `examples/github-stars` demonstrates the process.
   See `docs/design/approvals.md` §6.2.

5. **Deploy skill and preview/promote — done.** Deploys create previews by default;
   portal and CLI support promotion and rollback. The CLI uses OIDC device login
   and an XDG token cache. The portal's How to develop modal provides a
   deployment-specific agent skill. See `docs/features/onboarding.md`.

6. **Password/public visibility — done.** The portal manages shared passphrases;
   the edge verifies them through a throttled same-origin login and creates
   pseudonymous sessions. Public apps use anonymous callers, and switching to
   public visibility requires approval. The Access tab manages these workflows.

   Anonymous gateway calls share a per-IP+app fixed-window limit. Shared atomic
   Postgres counters enforce it across replicas (ADR-0011, issue #13).
   EDGE_TRUST_PROXY must name ingress addresses, not a hop count. The live ACA
   ingress was verified in the RFC 6598 range `100.64.0.0/10` on 2026-09-03.
   The later trust-proxy health check is recorded in ADR-0011's 2026-09-23 amendment.
   Deferred: bytesPerDay enforcement and total collection-size caps (app-data
   design §7).

7. **Session management — done.** The admin audit page reads gateway_calls.
   `GET /api/v1/sessions`, `POST /api/v1/sessions/revoke`, and the Sessions page
   support per-user revocation across apps, effective on the next request.
   The portal has only SELECT and DELETE on sessions (migration 20260921120000).
   See `docs/features/authentication.md`.

8. **Audit and usage — done.** Per-app and platform usage endpoints and pages read
   gateway_calls. Immutable external audit shipping was removed from scope on
   2026-09-17 because its requirement had not been adopted (ADR-0021 amendment).
   Ledger retention and erasure remain separate work in TODO.md.

The fetch-proxy and secret-backed connections **shipped as M4.5** (above) — built on the `helix-egress` mechanism plane from day one. The rest of v1.x and beyond (MCP-as-REST, Git-connect builds) stay in the architecture doc §12; don't plan them yet.

## 6. Working agreements

- Each milestone starts as a Claude Code planning session against this doc + the architecture doc.
- The edge dependency budget is enforced at review time: adding a package to `apps/edge` requires justification.
- Anything touching M3 auth code gets adversarial tests with it, not after.
- Architecture doc is the source of truth for *why*; when implementation diverges from it, update the doc in the same change.
