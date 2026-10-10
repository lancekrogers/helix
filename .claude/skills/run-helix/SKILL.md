---
name: run-helix
description: Build, run, and drive the Helix platform locally — boots helix-edge, helix-portal, helix-egress, the dev IdP and the portal SPA, then exercises them end to end. Use when asked to run or start Helix, smoke-test a change, verify a dependency bump, screenshot the portal UI, or check that the apps still work after an edit.
---

Helix is three services that only mean anything together: **edge** (data/policy plane, https), **portal** (control plane + SPA), **egress** (mechanism plane), plus **dev-idp** and the **portal SPA**. Drive all of it with one command:

```bash
node .claude/skills/run-helix/smoke.mjs
```

That boots every service, waits for health, runs 34 checks against the running system (including a real Chromium render of the SPA), cleans up, and exits non-zero on any failure. Paths below are relative to the repo root.

**It boots its own stack and never touches yours.** By default everything runs at a `+1000` port offset (edge `9080`, egress `9081`, dev-gateway `9082`, portal `4001`, dev-idp `4002`, SPA `6173`) against its own `helix_smoke` database and `app-bundles-smoke` blob container. Run it with `pnpm dev:*` up and your servers keep running and your dev database stays clean. The whole stack is resolved by `scripts/stack-env.mjs`; `--offset 0` opts back into the shared dev ports and database.

## Prerequisites

**None to install.** The devcontainer already provides Node 24, pnpm, Postgres (`db:5432`), Azurite, the mkcert certs, and the full auth env. If `pg_isready -h db` fails, you are outside the container — reopen in it.

```bash
pnpm install    # already done by post-create; re-run after dependency changes
```

The driver needs `PORTAL_DEV_TOKEN` and `DATABASE_URL` (both preset in the container) and exits 2 if the former is missing.

## Run (agent path)

```bash
node .claude/skills/run-helix/smoke.mjs                 # everything
node .claude/skills/run-helix/smoke.mjs --only edge     # one group
node .claude/skills/run-helix/smoke.mjs --no-browser    # skip Chromium
node .claude/skills/run-helix/smoke.mjs --keep          # leave services up to poke by hand
node .claude/skills/run-helix/smoke.mjs --offset 2000   # a different isolated stack
node .claude/skills/run-helix/smoke.mjs --offset 0      # share the dev ports + database
```

Groups: `idp`, `portal`, `edge`, `egress`, `spa`, `browser`, `cli`, `split-tls`, `split`.

### Split-domain mode

Set `HELIX_APPS_DOMAIN` (for example `helix-apps.localhost`) to host apps on a second loopback domain while the control plane stays on `local.helix.azxlabs.io`. A full smoke run then includes the `split` group (HTTP login, browser `Sec-Fetch-Site`, cookie scope, silent refresh). Run only that group with `--only split`:

```bash
HELIX_APPS_DOMAIN=helix-apps.localhost node .claude/skills/run-helix/smoke.mjs
HELIX_APPS_DOMAIN=helix-apps.localhost node .claude/skills/run-helix/smoke.mjs --only split
```

The run writes `sec-fetch-site.json` in its artifact directory with the handoff and API `Sec-Fetch-Site` values Chromium sent. If `.localhost` is classified as `same-site` with the control domain, the runner records **HYPOTHESIS REFUTED**, skips unverified cross-site checks, and you should also run the same-site fallback pair:

```bash
HELIX_APPS_DOMAIN=apps.local.helix.azxlabs.io node .claude/skills/run-helix/smoke.mjs --only split
```

Without a cached Chromium (`HELIX_SMOKE_CHROME` or Playwright’s binary), browser checks in the `split` group report SKIP — they are not counted as passes.

Connections consent popups in split mode are exercised by `pnpm lane:connections` with the same variable, not in the smoke runner.

Create the split TLS pair once per dev container (or when `local-helix-split.pem` is missing):

```bash
CAROOT=/workspace/.devcontainer/certs/caroot mkcert \
  -cert-file /workspace/.devcontainer/certs/local-helix-split.pem \
  -key-file /workspace/.devcontainer/certs/local-helix-split-key.pem \
  "*.local.helix.azxlabs.io" local.helix.azxlabs.io \
  "*.helix-apps.localhost" helix-apps.localhost \
  "*.apps.local.helix.azxlabs.io" apps.local.helix.azxlabs.io
```

Output is one line per check. Screenshots and per-service logs land in a printed temp dir (`/tmp/helix-smoke-*/`) — `signed-out.png`, `dashboard.png`, `apps-list.png`, and `edge.log`, `portal.log`, etc. **Look at the screenshots**; a mounted-but-blank page still passes the DOM assertion.

After `--keep`, stop everything with (the run prints this line with its own ports):

```bash
node scripts/free-port.mjs $(node scripts/stack-env.mjs --ports --offset 1000)
```

What it covers: OIDC authorization_code + PKCE through to an ID token; Prisma read + write + zod rejection; edge host routing, CSP injection, session gate (both branches), unknown-host 404; egress rejecting a forged instruction; the vite build served by the portal with hashed assets; the SPA rendering in real Chromium signed-out and signed-in; the esbuild CLI bundle querying the live portal.

Because the stack starts with an empty registry, the run first **seeds** it — deploying a one-file fixture app twice (`smoke-public`, `smoke-internal`) through the real `helix create` / `helix deploy --promote` path, so the edge and CLI groups always have something live to exercise. The slugs are fixed, so later runs reuse them instead of accumulating rows. Nothing SKIPs any more just because you happened to have no apps deployed.

The browser handle is `cdp.mjs` — a ~100-line Chrome DevTools Protocol client over Node 24's global `WebSocket`. It adds no dependency to the repo, which matters here (the edge is deliberately dependency-minimal). Reuse it for any new browser check.

## Run (human path)

Each service separately, in its own terminal:

```bash
pnpm dev:idp      # :3002   pnpm dev:portal   # :3001
pnpm dev:egress   # :8081   pnpm dev:edge     # :8080 (https)
pnpm dev:web      # :5173   Vite dev server, proxies /api to :3001
```

Apps are at `https://<slug>.local.helix.azxlabs.io:8080`. That wildcard resolves publicly to `127.0.0.1`, so no `/etc/hosts` edit is needed.

## Test suite

```bash
./check-and-lint.sh          # typecheck + lint + format + docs build + all tests — the CI gate
```

Required to pass before calling any change done. The smoke test is complementary, not a substitute: it catches wiring the unit tests mock out.

## Gotchas

- **`fetch()` cannot simulate a browser navigation.** Node's global `fetch` unconditionally sets `Sec-Fetch-Mode: cors` and silently drops whatever you pass. The edge's `isNavigation()` (`apps/edge/src/auth/gate.ts`) treats that header as authoritative, so a `fetch` to a gated app always takes the 401 subresource branch and never redirects. Use the `rawGet()` helper (`node:https`) in `smoke.mjs`.
- **The edge's TLS cert has no `localhost` SAN.** It covers `*.local.helix.azxlabs.io` and the bare base domain only. `https://localhost:8080/health` fails TLS verification even though the socket is listening — it looks exactly like "the service didn't start." Always address the edge by its base domain.
- **`apps/edge/.env.local` overrides the container env to real Entra.** `EDGE_OIDC_ISSUER` is `login.microsoftonline.com/...`, not `localhost:3002`, so the edge's login flow leaves the machine and **dev-idp is not in the edge's path**. The driver tests oidc-provider by driving `:3002` directly. Don't chase this as a bug.
- **The session gate is content-negotiated.** 401 JSON for API-style requests, 302 to `auth.<base>/start` only for navigations. A bare `curl` against a gated app returns 401 and looks broken. It isn't.
- **`pnpm dev:*` does not forward SIGTERM** to the `tsx` child it spawns. Kill the process group (`spawn(..., {detached:true})` then `process.kill(-pid)`) or just run `scripts/free-port.mjs`. Ports routinely survive a previous session.
- **Every `dev` script frees its port before binding**, and the port it frees now comes from the env (`${EDGE_PORT:-8080}` and friends), not a literal. That is what makes a second stack safe: `env $(node scripts/stack-env.mjs --env --offset 1000) pnpm dev:portal` binds `:4001` and leaves `:3001` alone. Before this, any offset stack still SIGKILLed the base port.
- **The SPA's token is per-tab `sessionStorage`,** key `azx.portal.token`, value `{"token":"..."}` (`apps/portal-web/src/auth/tokenStore.ts`). Seeding it with `PORTAL_DEV_TOKEN` is how the driver reaches authenticated screens without an interactive Entra login.
- **There is no hard-delete API for apps** — only archive. The driver creates a `smoke-<uuid>` app to exercise a Prisma write and removes the row with `psql` afterwards. If a run is killed mid-flight, clean up with:

  ```bash
  psql "postgresql://helix:helix@db:5432/helix_smoke" -c "DELETE FROM apps WHERE slug LIKE 'smoke-%';"
  ```

  Note the database: the run's rows live in `helix_smoke`, not your dev database. Dropping the whole thing (`DROP DATABASE helix_smoke`) is also safe — the next run recreates and migrates it in about a second.

- **Rebuilding the SPA under a running portal serves stale routes.** `routes/spa.ts` registers `@fastify/static` with `wildcard: false`, which globs `apps/portal-web/dist` once at registration and registers a route per file. Run `pnpm --filter @azx-pbc/portal-web build` while `pnpm dev:portal` is up and the new hashed filenames match nothing — every asset falls through to the deep-link handler and returns `index.html` as `text/html`, so the page loads and React never mounts. Restart the portal after a build. `smoke.mjs` builds before it boots for this reason.
- **No browser driver ships in the repo** (no playwright, no `chromium-cli`), but a Chromium is cached at `~/.cache/ms-playwright/chromium-*/chrome-linux/chrome`. `cdp.mjs` finds it; override with `HELIX_SMOKE_CHROME`. If it's absent the browser group reports SKIP rather than failing.

## Troubleshooting

| Symptom                                                                           | Fix                                                                                                                   |
| --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `edge never became healthy (fetch failed)` but `edge.log` says `Server listening` | You probed `localhost`. Use `https://local.helix.azxlabs.io:8080`.                                                    |
| `session gate: expected 302, got 401`                                             | You used `fetch`, not `rawGet` — see the first gotcha.                                                                |
| Health check hangs on every service                                               | Ports held by a previous run: `node scripts/free-port.mjs $(node scripts/stack-env.mjs --ports --offset 1000)`.       |
| `portal` unhealthy, log mentions Prisma                                           | `pnpm --filter @azx-pbc/portal db:deploy`, then re-run.                                                               |
| Browser group SKIPs                                                               | No cached Chromium. Set `HELIX_SMOKE_CHROME=/path/to/chrome`.                                                         |
| `PORTAL_DEV_TOKEN is not set` (exit 2)                                            | You're outside the devcontainer.                                                                                      |
| Edge serves an app but assets 404                                                 | Azurite isn't up: `curl -s -o /dev/null -w '%{http_code}' http://azurite:10000/devstoreaccount1` should not be `000`. |
