# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

> Start with [`TOUR.md`](TOUR.md) for the repository map. This file is the
> working reference for commands, environment, and contribution rules.

**Helix** hosts AI-generated static web apps. It treats every hosted app as
untrusted and restricts access per app. Before non-trivial design work, read
`docs/platform-architecture.md` and `docs/platform-project-plan.md`. Architecture
Decision Records in `docs/adr/` take precedence over older prose. Feature docs
describe current behavior; design docs describe intended behavior; reviews are
dated snapshots; runbooks are procedures. Use [`docs/README.md`](docs/README.md)
to find the right document and location for new docs. Follow-up work is in
[`TODO.md`](TODO.md).

**Current status: deployed on Azure (M5); feature work at M4.5 — Egress & Connections.** The three planes run in production on Container Apps against real Entra OIDC, wildcard TLS, and a live Key Vault — `infra/azure` (Bicep) is the source of truth for the topology, and `infra/azure/README.md` is the operational reference. The outstanding M5 residual is a real pilot app end to end. **Everything still runs fully locally** — `apps/dev-idp` stands in for Entra, the dev AES-GCM envelope for Key Vault, Azurite for Blob — so treat "local" below as the development path, not the only deployment. **Where a doc says something is "local only", treat it as stale unless it agrees with this line.**

What has landed, and where the maintained detail lives — prefer these over prose here; they are kept current, a status paragraph is not:

- **Auth** (§4.2/Appendix A) — central callback on `auth.<base>`, one-time handoff token, `__Host-session` cookies, the app-host session gate, group re-checks, silent refresh, and `password` visibility for shared-password apps: `docs/features/authentication.md`, `apps/edge/README.md`. Real Entra in the deployed platform, `apps/dev-idp` locally — the flow is identical either way, the issuer is one env-level swap.
- **The `/_api/*` gateway** (§6.1) — LLM proxy and app-data in three scopes (per-user RLS, write-only collections, app-shared): `docs/features/`, `docs/design/app-data-storage.md`.
- **Fetch-proxy + secret-backed connections** (M4.5) — edge authorizes and mints a signed attested instruction, `apps/egress` verifies it, injects the connection secret, and applies SSRF controls: ADR-0005, ADR-0006, ADR-0035, `apps/egress/src/ssrf.ts`.
- **Observability** (ADR-0037) — hand-placed spans and metrics on the three services behind an **OTLP-only boundary**, inert unless an endpoint is configured; on Azure both collectors feed one App Insights component, and the alert modules under `infra/azure/modules/alerts*.bicep` consume it — the platform's own telemetry, an outside HTTP probe (Application Insights standard tests on `/health`, which read the **body** because it answers 200 in every state), Azure platform metrics, and a cost budget: `docs/features/observability.md`, `packages/telemetry/README.md`, and `docs/design/logging.md` for levels/correlation/redaction. See **Telemetry ships with the change** below — this is a standing expectation, not a milestone.
- **Portal SPA** (`apps/portal-web` — Vite + React 19 + Mantine + TanStack Query + React Router; the one package on `moduleResolution: bundler`): every screen is real and wired. Per-app RBAC (owner/editor/viewer) is a not-yet-built v1 sub-feature; the placeholder card that marked it came off the Access tab in the 2026 selector redesign, and no `PreviewBadge` remains in the SPA — never silently fake. Authorization posture is [ADR-0007](docs/adr/0007-portal-authz-v0.md); the BOLA half is closed by the `ownsApp` preHandler, RBAC is not. See `docs/features/portal-web.md`.

Constraints from that work that outlive any status line:

- The SPA's **only build-time config is the portal origin.** Deployment topology comes from the public `GET /api/v1/config` at runtime, and every app the API returns carries a control-plane-computed `url`. Never reintroduce a `VITE_*` domain var or derive the apps host from `window.location`.
- **`packages/secret-store` stays zero-dependency** — it is consumed by the mechanism plane. `packages/directory` keeps the same posture by convention (it is portal-only, so nothing forces it): hand-rolled Graph REST over global `fetch`, credential injected as a one-function seam.
- **`packages/directory` has no member-enumeration method, and that absence is the decision** (ADR-0040). The `GroupMember.Read.All` grant permits reading the membership of every group in the tenant; keeping `/members` out of the interface is what makes the real blast radius auditable by reading one file. Adding one is a new ADR, not a new method.
- **`helix_edge` has no grant on `app_secrets` at all**, so an edge RCE can't dump a single key. `role-split.integration.test.ts` is what holds that line.

## Commands (from repo root)

| Command                                           | What                                                                                                                                                                                |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm dev:edge`                                   | Run helix-edge (`:8080`, **https** in dev — apps at `https://<slug>.local.helix.azxlabs.io:8080`, login on `auth.local.helix.azxlabs.io`, platform `GET /health`)                   |
| `pnpm dev:egress`                                 | Run helix-egress (`:8081`, mechanism plane — the fetch-proxy `POST /proxy` + secret injection; needs `helix_egress` role + the dev KEK)                                             |
| `pnpm dev:portal`                                 | Run helix-portal (`:3001`, registry + deploy API)                                                                                                                                   |
| `pnpm dev:idp`                                    | Run the local OIDC issuer (`:3002`, `apps/dev-idp` — fixture users + clients; dev only, never deployed)                                                                             |
| `pnpm dev:web`                                    | Run the portal SPA dev server (`:5173`, Vite; proxies `/api` + `/health` to :3001). `pnpm --filter @azx-pbc/portal-web build` makes the portal serve it at :3001                    |
| `pnpm dev:docs`                                   | Run the public docs site dev server (VitePress, `apps/docs` — operator + app-author guides, published to GitHub Pages by `.github/workflows/docs.yml`)                              |
| `pnpm --filter @azx-pbc/portal db:migrate`        | Create/apply a Prisma migration (dev). Also `db:deploy`, `db:reset`, `db:generate`                                                                                                  |
| `pnpm --filter @azx-pbc/helix-cli helix -- <cmd>` | Run the `helix` CLI (`deploy`, `create`, `versions`, `promote`, `rollback`). Runs in `packages/cli`; for real deploys run it from an app dir instead — see `packages/cli/README.md` |
| `./check-and-lint.sh`                             | Poor-man's CI: typecheck + lint + format check + docs build + tests in one pass (add `--fix` to auto-fix first)                                                                     |
| `just`                                            | List recipes for the dev servers, the gate, the database, the CLI, images, and Bicep (modules in `.justfiles/`). `just check` runs `./check-and-lint.sh`                            |

The portal API lives under `/api/v1`. Mutating routes take a bearer token through the verifier chain — an IdP-minted JWT (`helix login`) or `$PORTAL_DEV_TOKEN` (CI/dev fallback); reads now require the same token (only `/health` + the auth-config bootstrap stay public). Deploys land as `preview` versions — promotion to live is a separate step (architecture §5.1).

The standard workspace scripts (`install`, `typecheck`, `lint`, `format`, `test`) are in the root `package.json`. Per-package scripts also run via `pnpm --filter @azx-pbc/edge <script>`.

**Before committing, opening a PR, or reporting a change as finished, run
`./check-and-lint.sh` (or `--fix`) from the repo root and get a clean pass.** It
runs typecheck, lint, format check, docs build, and the full test suite. Fix
failures and rerun the gate before proceeding. Targeted checks are useful during
iteration but do not replace it. CI uses the same script, split into static
checks (`typecheck lint format docs`) and tests (`test`, requiring Postgres and
Azurite). Running the script without step names covers both.

## Environment

Work inside the **dev container** (VS Code: _Reopen in Container_). It provides Node 24, pnpm, and the `db` (Postgres 18) + `azurite` (Blob) services, with `DATABASE_URL`, `AZURE_STORAGE_CONNECTION_STRING`, and the M3 auth env (`EDGE_OIDC_*`, `EDGE_AUTH_SECRET`, `EDGE_TLS_*`, `PORTAL_OIDC_*`) already set. The local IdP is **not** a compose service — it runs in the workspace container (`pnpm dev:idp`) so its issuer URL (`http://localhost:3002`) reads identically from the host browser and from in-container back-channels. mkcert TLS certs for `*.local.helix.azxlabs.io` are generated by post-create into `.devcontainer/certs/` (gitignored). `pnpm install` runs on create. Node 24 LTS is required (`engines.node >=24`).

## Architecture

The system is **three deployable containers plus managed storage**, split along the trust boundary (architecture §3):

- **`apps/edge` — helix-edge, the data/policy plane.** Stateless. Terminates all untrusted app-user traffic (`*.local.helix.azxlabs.io` in dev, `*.azx.helix.azxlabs.io` in prod): host routing, session auth + OIDC handoff, CSP injection, asset serving from Blob, and the `/_api/*` gateway — the LLM proxy, app-data (user/collection/shared), and the **fetch-proxy policy** (authz/quota/audit, then a signed instruction to egress). Runs as the least-privilege `helix_edge` role: a read-only registry projection, INSERT-only metering/collections, RLS-partitioned app-data — **no registry-write and no secret-read** access.
- **`apps/portal` — helix-portal, the control plane.** Privileged: portal UI/API, deploy endpoint, registry writes, capability approvals, secret writes. Not routable from app subdomains. Owns the Postgres schema and all migrations (Prisma 7, pg driver adapter); the edge only reads a cached projection.
- **`apps/egress` — helix-egress, the mechanism plane.** The only component holding plaintext connection secrets or a route to the public internet. Internal-only (`POST /proxy`, never app-user-facing): verifies the edge's attested instruction, resolves+injects the secret under the `helix_egress` role, enforces SSRF controls, and streams the outbound call back. Its own network egress zone in prod; built as its own container from day one rather than extracted later.
- **`packages/secret-store` — `@azx-pbc/secret-store`.** The `seal`/`open`/`destroy` custody seam shared by the portal (write) and egress (read): dev AES-GCM envelope / prod Key Vault behind one interface. **Zero runtime dependencies** — it is consumed by the mechanism plane, so the Key Vault impl is hand-rolled data-plane REST over global `fetch` with the credential injected as a one-function `GetVaultToken` seam (egress hand-rolls the managed-identity call; the portal injects `DefaultAzureCredential`). Keep it dependency-free.
- **`packages/directory` — `@azx-pbc/directory`.** Group search and id→name resolution for the Access tab's picker (ADR-0040): `EntraDirectory` (hand-rolled Graph v1.0 REST over global `fetch`, credential as a one-function `GetGraphToken` seam), `StaticDirectory` (dev-idp fixtures + CI), and an unavailable variant that **reports** its own absence as a value rather than throwing — so a tenant that never granted `GroupMember.Read.All` gets a working Access tab with an explicit banner, not a broken one. **Portal-only**: the edge never calls Graph, never holds the credential, and does nothing with groups but intersect two string arrays.
- **`packages/telemetry` — `@azx-pbc/telemetry`.** Boot-time OpenTelemetry, and the **only** place in the repo that imports an OpenTelemetry SDK package (ADR-0037 decisions 3–4). `startTelemetry(SERVICE_NAME)` is called from the three `server.ts` files and nowhere else; from `buildApp()` inward, code imports the dependency-free `@opentelemetry/api` facade, which no-ops when no provider is registered — that is what keeps `buildApp()` pure and lets tests inject requests without an exporter. No vendor telemetry SDK name appears outside `infra/`; changing backends is a Bicep edit. Also ships `@azx-pbc/telemetry/testing` (`startRecordingTelemetry`) for asserting spans and metrics in-process.
- **`packages/shared` — `@azx-pbc/shared`.** The zod schemas validated at every boundary. Note it exports `./src/index.ts` directly — **no build step**, so consumers get the TypeScript source.

`packages/cli` — `@azx-pbc/helix-cli`, the `helix` CLI — landed in M1 (zips a build dir or a prebuilt bundle and drives the deploy API) and is **published to public npm** (`npm i -g @azx-pbc/helix-cli`) from `.github/workflows/release-cli.yml` on a `cli-v*` tag, via trusted publishing (OIDC, no `NPM_TOKEN`) with provenance — ADR-0032. It is the only non-`private` package in the repo and the only one that emits JS. And `apps/portal-web` (the React SPA) is real and wired (see above). `packages/deploy-skill` is the **agent skill bundle** — a templated `SKILL.md` teaching an agent how to build and deploy a Helix app, rendered for this deployment and handed out by the portal SPA's **How to develop** modal (`docs/features/onboarding.md`). `infra/azure` (Bicep) is the deployed Azure topology and the source of truth for it — see `infra/azure/README.md`.

### The edge is the trusted path

**Hard rule: `apps/edge` is dependency-minimal.** Every npm package there is code inside the trusted path, so adding a runtime dependency requires justification at review time (project plan §6). No ORM in the edge — hand-written SQL. Never block the event loop; pipe streams, never buffer LLM responses.

### App boot and the `/health` contract

Every service splits `buildApp()` (pure, no listen) from `server.ts`, so tests build the app and inject requests rather than binding a port. The `/health` endpoint validates its own response through `HealthStatusSchema` so the contract is identical across services. That contract is a three-state roll-up (`ok`/`degraded`/`error`) plus an optional generic `checks[]` array, not a liveness boolean — the edge reports its registry projection's freshness there (ADR-0025). **It always answers HTTP 200**, in every state: the body carries the degradation, because a non-200 would let a liveness probe restart a replica that is serving correctly from a stale copy. Portal and egress report liveness only (no `checks`).

## Conventions

- **TypeScript everywhere, ESM, Node 24.** Strict `tsconfig.base.json` (`strict`, `noUncheckedIndexedAccess`, `verbatimModuleSyntax`, `isolatedModules`), extended per package. Because of `verbatimModuleSyntax`, type-only imports must be written as `import type` / `import { type X }`. ESM import specifiers use `.js` extensions even for `.ts` sources (`nodenext`).
- **Versions via the pnpm catalog** in `pnpm-workspace.yaml` — packages reference `catalog:` instead of pinning; bump in one place.
- **zod at every boundary** (`@azx-pbc/shared`); inferred types travel with the schemas.
- **Tests** are colocated `*.test.ts` under each package's `src/`. Vitest runs **two projects**: `node` for every backend package, and `portal-web` (jsdom + the React plugin, defined in `apps/portal-web/vite.config.ts`) for the SPA's `*.test.tsx`.
- **Anything touching M3 auth code gets adversarial tests with it, not after** (project plan §6). The OIDC handoff is the most security-sensitive code in the platform and gets a dedicated review pass.

### Documentation and comments

Use plain English and short paragraphs. State behavior or a requirement first,
then explain the reason when it helps the reader. `apps/docs/` is the style
reference. Keep commands, contracts, security limits, and decision links precise.

Comments should explain a non-obvious constraint, a failure case, or a choice a
maintainer could otherwise get wrong. Remove comments that only repeat the code.
Keep implementation history and rejected alternatives in an ADR when they matter;
do not narrate earlier drafts or review arguments in source comments. Avoid
rhetorical questions, dramatic warnings, and repeated claims that a feature is
"real" or "deliberate". Preserve dated reviews as historical records.

### Telemetry ships with the change

**A change that adds a seam adds its instrumentation in the same change** — you should not have to be asked for it. "Seam" means a route or gateway capability, an outbound hop, a background loop, a new failure mode an operator would want to alert on, or a new decision point that can deny a request. The maintained detail is `docs/features/observability.md` (what exists today, plus the two things to know before writing an alert on it), [ADR-0037](docs/adr/0037-platform-observability-otlp-boundary.md) (the decisions, and the Amendments the implementation forced), `packages/telemetry/README.md` (the SDK boundary and the off-by-default rules) and `docs/design/logging.md` (levels, `reqId` vs `trace_id`, the `event` convention, URL redaction). Read those before adding a signal; the rules that decide whether a change is done:

- **Names are constants, never literals.** Span names, attribute keys and instrument names live in `packages/shared/src/telemetry.ts` (`SPAN_*`, `ATTR_*`, `INSTR_*`, `ROUTE_*`) so the emitter, the tests and any dashboard cannot drift. Add the constant, then use it.
- **Spans come from the service's own `telemetry.ts` helpers**, not from an inline `tracer.startSpan`. On the edge that is `withRootSpan` / `spanRoute`: `root: true` (see the propagation rule below), graded to ERROR from a 5xx **reply** as well as from a throw — this codebase signals failure by returning normally — and ended at stream close, not when the handler is wired up. New instruments go on the service's one `instruments()` object so a call site can't miss one — the portal deliberately has none (ADR-0037 decision 8), so giving it one is a decision, not a detail.
- **Every attribute and every metric dimension must be bounded and non-personal.** `appId` is a dimension; **`userOid` is never one**. Metering, budgets and audit stay the ledger's job (ADR-0021) — an operational counter that happens to count the same events is never reconciled against it.
- **Never record a whole URL.** No `url.full`, `http.url`, `http.target` or `url.query`, ever: several platform URLs carry a live credential in the query string, and a span attribute lands in the same retained store a log line does. Use `spanUrlAttributes` (`@azx-pbc/shared/logging`) / `url.path` + `http.route` on spans, and log URLs under the top-level `url` key so `loggerOption`'s serializer redacts them. Egress attributes are a **hardcoded allowlist** with no header name or value, and egress spans record no exception — its error text can embed credential material. ESLint enforces the forbidden keys and the SDK boundary; a lint error here is a security rule, not a style nit.
- **Traces propagate inward only.** The edge and the portal must never continue a trace from an inbound `traceparent` (app-user traffic is untrusted): `propagation.extract` is lint-banned there, the propagator is inject-only, and egress is the one extractor.
- **Telemetry must never be able to fail a request.** Nothing synchronous in the hot path, exporter errors log at `warn` and drop, and the whole subsystem stays inert with no endpoint configured — which is the platform's default state, so verify your change still behaves with `OTEL_SDK_DISABLED=1`.
- **Assert it with a test, in the same change.** `startRecordingTelemetry` from `@azx-pbc/telemetry/testing` registers real in-memory providers, so spans and metrics are assertable without an exporter. The adversarial suites (`apps/edge/src/spanRedaction.test.ts`, `traceBoundary.test.ts`, `apps/egress/src/spanAttributes.test.ts`) scan **every** attribute of **every** span rather than one field — a span added later without thought fails a test instead of leaking quietly, so extend those rather than routing around them.
- **Update the inventory.** The span and instrument tables in `docs/features/observability.md` are the list of what the platform emits; a new signal that isn't in them is undiscoverable. Locally, Jaeger runs as the `otel-collector` compose service and the trace UI is on <http://localhost:27686> — look at the trace you just added.

Deliberately _not_ expected: auto-instrumentation (rejected outright — it monkey-patches `http`, `undici` and `pg` at require time inside the process that terminates untrusted traffic), an OTel log bridge, per-app telemetry for hosted apps, and tail sampling. Those are deferred decisions, not gaps to fill opportunistically; reopening one is an ADR.
