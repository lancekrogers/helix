# helix-edge

The data plane (architecture §3): stateless, terminates all `*.azx.helix.azxlabs.io` traffic. As of **M3 (local half)** it serves deployed apps behind real authentication: host routing, a cached registry projection (Postgres LISTEN/NOTIFY), the §4.2/Appendix A OIDC login flow (central callback on `auth.<base>`, one-time handoff token, `__Host-session` cookies, server-side sessions in Postgres), `/_api/me`, group-based visibility checks, silent refresh, asset streaming from Blob (managed-identity bearer in prod, hand-rolled SharedKey dev/Azurite-only — issue #15), baseline CSP injection, and 404/410 (+ `Clear-Site-Data`) semantics.

**Hard rule: dependency-minimal.** Runtime deps are exactly `fastify`, `pg`, `undici`, `zod`, `jose`, `openid-client`, `@azx-pbc/shared` — the M3 additions are the two named in project plan §1. Adding a package here requires justification at review time (project plan §6). No ORM, no Azure SDK, no cookie library — SQL is hand-written, blob reads use the managed identity (an AAD token fetched over `undici`, still no SDK) or hand-rolled SharedKey signing in dev, and cookie parsing is ~30 lines (`src/auth/cookies.ts`).

## Request flow (app hosts)

`<slug>.local.helix.azxlabs.io` → registry projection (slug → live version + visibility) → **session gate** → `apps/<appId>/<n>/<path>` from Blob, streamed.

The gate follows architecture §4.2 and Appendix A:

1. Without a session cookie, top-level navigation redirects to `auth.<base>/start`;
   fetches and subresources receive 401. Detection uses Sec-Fetch-Mode, then Accept.
2. The auth host performs OIDC code exchange with PKCE and nonce checks, checks
   app visibility, and creates a pending session.
3. A 30-second, single-use, audience-bound token reaches `/_auth/complete` on
   the app host. An atomic update redeems it and creates a host-only session cookie.
4. Sessions expire after 8 hours by default. After the refresh interval (1 hour
   by default), navigation attempts silent re-authentication with prompt=none;
   gateway fetches receive `401 refresh_required`. Passive assets can still load
   until hard expiry. Refresh captures current group membership.
5. Origin-checked `POST /_auth/logout` deletes the session. Admin revocation
   deletes all sessions for a user and takes effect on the next lookup.

`GET /_api/me` returns `{user: {id, displayName, email}}`. The id is the canonical
principal claim (Entra oid by default, ADR-0048); email is nullable. Group
snapshots are not exposed to app code.

Every app response carries CSP, including SVG and XML. HTML uses
`Cache-Control: no-cache`; other assets use `private, max-age=300` with ETag
revalidation. HTML-accepting paths that miss an asset fall back to `index.html`.
Unknown apps or apps without a live version return 404. Archived apps return
410 with `Clear-Site-Data: "cache", "storage"` before the session gate.

App-supplied service workers are rejected because a root-scoped worker could
intercept the auth handoff URL. Plain web workers remain allowed. The offline
capability (ADR-0035) serves a platform worker at `/_helix/sw.js`, limited to the
approved scope. Its registration script is inline so offline startup does not
need a fetch to the uncached `/_helix/` namespace. Revocation or archive serves
a worker that clears its cache and unregisters itself.

Reserved platform routes never fall through to Blob. Platform hosts expose
`GET /health`; the auth host also handles `/start` and `/callback` — and
proxies `/connections/*` to the portal: the consent
callback and the portal-rendered completion pages are control-plane surfaces
reached at the auth host through one narrow reverse proxy. The proxy carries a
per-call internal JWT (`aud: portal`), strips any inbound version of that
header, forwards only a three-name header safelist, and 503s fail-closed when
`EDGE_PORTAL_URL` is unset. On app hosts `/connections/` stays an ordinary
asset path.

## Configuration

| Env var                                           | Default                                  | Meaning                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`                                    | (required)                               | Postgres: registry projection (read) + sessions (read/write)                                                                                                                                                                                                                                                                                                                                      |
| `EDGE_PORTAL_URL`                                 | unset                                    | Internal base URL of helix-portal (plain HTTP behind the ingress). Without it — or without `HELIX_INTERNAL_SECRET` — the auth host's `/connections/*` proxy 503s fail-closed; nothing else changes                                                                                                                                                                                                |
| `AZURE_STORAGE_BLOB_ENDPOINT`                     | (prod)                                   | Blob endpoint for **managed-identity** reads (with `AZURE_CLIENT_ID`); refused-in-prod alternative below. Wins when both are set (issue #15)                                                                                                                                                                                                                                                      |
| `AZURE_CLIENT_ID`                                 | (prod)                                   | User-assigned MI client id for the AAD token fetch (`IDENTITY_ENDPOINT`/`IDENTITY_HEADER` injected by Container Apps)                                                                                                                                                                                                                                                                             |
| `AZURE_STORAGE_CONNECTION_STRING`                 | (dev)                                    | Blob/Azurite for asset reads via SharedKey — **dev/Azurite only, refused when `NODE_ENV=production`**                                                                                                                                                                                                                                                                                             |
| `BLOB_CONTAINER`                                  | `app-bundles`                            | Container the portal deploys into                                                                                                                                                                                                                                                                                                                                                                 |
| `EDGE_BASE_DOMAIN`                                | `local.helix.azxlabs.io`                 | Apps serve on `<slug>.<this>`; auth on `auth.<this>`                                                                                                                                                                                                                                                                                                                                              |
| `EDGE_OIDC_ISSUER`                                | unset                                    | OIDC issuer (dev: `http://localhost:3002`; later: Entra). All four auth vars set together, or none                                                                                                                                                                                                                                                                                                |
| `EDGE_OIDC_CLIENT_ID` / `_CLIENT_SECRET`          | unset                                    | The edge's confidential client at the issuer                                                                                                                                                                                                                                                                                                                                                      |
| `EDGE_AUTH_SECRET`                                | unset                                    | base64, ≥32 bytes; HKDF-derived into handoff + flow-cookie keys                                                                                                                                                                                                                                                                                                                                   |
| `EDGE_OIDC_ALLOW_INSECURE`                        | unset                                    | Permit an `http://` issuer (local dev-idp only)                                                                                                                                                                                                                                                                                                                                                   |
| `EDGE_OIDC_GROUPS_CLAIM` / `EDGE_OIDC_SCOPES`     | `groups` / `openid profile email groups` | Claim + scopes for group visibility. **The default is shaped for the dev-idp, which serves `groups` as a real scope. Entra does not** — it has no `groups` delegated permission and emits group claims from the app registration instead, so an Entra install must set `EDGE_OIDC_SCOPES=openid profile email`. `infra/azure` already hardcodes that, so this only bites a hand-rolled deployment |
| `EDGE_SESSION_TTL_MS` / `EDGE_SESSION_REFRESH_MS` | 8 h / 1 h                                | Hard session cap / silent-refresh due time                                                                                                                                                                                                                                                                                                                                                        |
| `EDGE_TLS_CERT_FILE` / `EDGE_TLS_KEY_FILE`        | (required in dev)                        | Edge-terminated TLS (mkcert). **Required outside production** — the platform is HTTPS-only. Prod leaves them unset (ingress owns the cert)                                                                                                                                                                                                                                                        |
| `EDGE_PUBLIC_PORT`                                | listen port                              | Public port for built redirect/cookie URLs (prod: 443; the scheme is always https)                                                                                                                                                                                                                                                                                                                |
| `EDGE_DEV_ALLOW_UNAUTHENTICATED`                  | unset                                    | **Dev only** (refused in production): skip the session gate. Does **not** relax TLS                                                                                                                                                                                                                                                                                                               |
| `EDGE_ALLOW_PUBLIC_APPS`                          | `false`                                  | Set `true` to permit `public` (anonymous) apps; otherwise assets 403 and `/_api/*` refuses the anon caller, even for an already-public app. "Allow" polarity, opt-in (parse → `=== "true"`). Set the matching `PORTAL_ALLOW_PUBLIC_APPS` too                                                                                                                                                      |
| `EDGE_ALLOW_PASSWORD_APPS`                        | `false`                                  | Set `true` to permit `password` (shared-passphrase) apps; otherwise assets 403, `/_api/*` refused, and the `/_auth/login` challenge 404s. Pair with `PORTAL_ALLOW_PASSWORD_APPS`                                                                                                                                                                                                                  |
| `EDGE_IMG_SRC_EXTRA`                              | _(empty)_                                | Comma-separated `https://host[:port]` origins appended to every app's Report-Only `img-src` (never `connect-src`). Operator-trusted image hosts only — do not list an image proxy that fetches attacker-chosen URLs. Azure: `imgSrcExtra` in `infra/azure/main.bicep`                                                                                                                             |
| `EDGE_RECONCILE_INTERVAL_MS`                      | `60000`                                  | Projection full-reload safety net (±20% jitter). Must be a positive number — the edge **refuses to boot** otherwise, because `NaN` would reach `setTimeout` as ~0 ms and hot-loop the DB                                                                                                                                                                                                          |
| `EDGE_STATEMENT_TIMEOUT_MS`                       | `10000`                                  | Per-query `statement_timeout` on every edge Postgres pool (pool-exhaustion DoS guard, ADR-0002); `0` disables                                                                                                                                                                                                                                                                                     |
| `EDGE_PORT` / `PORT`                              | `8080`                                   | Listen port                                                                                                                                                                                                                                                                                                                                                                                       |

Two fail-closed stances. **Transport:** the platform is HTTPS-only — outside `NODE_ENV=production` the edge refuses to boot without `EDGE_TLS_*` (`__Host-` cookies need Secure; app crypto APIs need a secure context). **Auth:** with no auth block and no dev bypass, app hosts serve nothing (503); the bypass throws under production.

## Logging and redaction

Structured JSON to stdout (pino via Fastify), off under `NODE_ENV=test`. Several platform URLs carry a live credential in the query string — Appendix A step 8's `/_auth/complete?token=…`, the auth host's `/callback?code=…`, the portal SPA's own `/auth/callback?code=…` — so **`@azx-pbc/shared/logging`** replaces Fastify's default request serializer with one that rewrites those values to `REDACTED` before anything is written. It is shared deliberately: `loggerOption()` is wired into all four Fastify services (edge, dev gateway, portal, egress), because the same credential shape reaches more than one of them and a per-service copy would drift.

Two rules:

- **By parameter name**, on every route — not just the auth ones, since a probe or misroute carrying the same query gets logged too. The list covers the platform's own (`token`, `code`, `id_token`, `access_token`, `refresh_token`, `session`, `sid`) plus the third-party conventions an app might put on a proxied URL (`api_key`, `key`, `sig`, `signature`, `secret`, `client_secret`, `password`, …) and `error_description` (IdP-chosen free text). Names match case-insensitively and after percent-decoding; the scan treats `&`, `;` and `#` as separators, so there is no unscanned window. Everything else is byte-identical.
- **`/_api/fetch/<target>` is special-cased**, because a name list can't cover an arbitrary upstream: the shim splices the target in unencoded (`PREFIX + u.href`), so _its_ query becomes ours, and a percent-encoded target hides the whole thing in the path. The rule is origin + path, target query dropped wholesale — `/_api/fetch/https://api.example.com/v1?REDACTED`. `origin` also drops `user:pass@` userinfo, and an unparseable target is dropped entirely. The `gateway_calls` ledger already records the origin, so nothing is lost.

**What this does not cover.** The guarantee is scoped to the `req.url` **field**. Fastify itself interpolates the raw URL into two log _messages_ (`lib/reply.js` — `FST_ERR_REP_ALREADY_SENT` and the double-send warning), both of which need a bug in one of our own handlers to fire; and any hand-rolled log call must pass `redactUrl(req.url)` itself. Tests: `packages/shared/src/logging.test.ts` (the rules) and `src/logging.test.ts` (a real pino round-trip on the request and error paths).

**Ops note — the hops we don't own.** This closes the container's own logs, which in Azure is the retention surface that matters: Container Apps ships container stdout to the environment's Log Analytics workspace (`appLogsConfiguration` in `infra/azure/modules/aca-environment.bicep`, 30-day retention). The ACA ingress persists no access log — **verified 2026-09-23 on both production installs**: a marker in `/_auth/complete?token=…` appeared nowhere in either environment's workspaces except the edge's own stdout line, as `token=REDACTED`, and App Insights `AppRequests` recorded the request with an empty `Url`. Note that is an Azure default, not something this repo sets. ACA does offer an ingress access log (the `ContainerAppHTTPLogs` diagnostic category, full request URIs), and it stays off only because `appLogsConfiguration` uses the `log-analytics` destination, which carries console and system logs alone, and no diagnostic setting exists on the environment. **Switching the destination to `azure-monitor` or adding a diagnostic setting with that category (or `allLogs`) turns it on — mask the query string first.** Re-verify the same way after any change there (same caveat as `EDGE_TRUST_PROXY` — ingress properties are per-deployment and can change underneath you). **Anything added in front of the edge — Front Door, App Gateway/WAF, a CDN, an nginx sidecar — logs full request URIs by default and must have query-string logging disabled or the same parameters masked.** The handoff token stays bounded regardless (single-use, 30 s TTL, audience-bound to one app + one session row), and both legs of the redirect that carries it — the callback's 302 and `/_auth/complete`'s own response — send `Referrer-Policy: no-referrer` + `Cache-Control: no-store`, so it doesn't leak via Referer or an intermediary cache. Browser history is the residual we can't erase — see issue #20.

## Health and staleness

`GET /health` on platform/auth hosts returns the shared `HealthStatusSchema` — and on app hosts it
is just an asset path (an app may ship its own `/health` file). Beyond liveness it reports two
sub-checks: the registry projection's freshness (ADR-0025) and the trust-proxy walk (ADR-0011):

```json
{
  "status": "degraded",
  "service": "helix-edge",
  "uptime": 812,
  "checks": [
    {
      "name": "registry-projection",
      "status": "degraded",
      "detail": "projection last loaded 412s ago (> 5× the 60s reconcile interval); serving stale",
      "lastSuccessAt": "2026-07-30T12:00:00.000Z",
      "metrics": { "consecutiveLoadFailures": 7, "staleForSeconds": 412 }
    },
    {
      "name": "trust-proxy",
      "status": "ok",
      "metrics": {
        "forwardedSeen": 512,
        "forwardedResolved": 512,
        "windowSeen": 50,
        "windowResolved": 50
      }
    }
  ]
}
```

Why it exists: the projection **serves stale on a load failure** by design (architecture §7), which
without a signal means a sustained DB failure serves an out-of-date access rule forever and reads
green. Thresholds (`src/registry/health.ts`, ratios to `EDGE_RECONCILE_INTERVAL_MS`):

| State      | When                                                                                            |
| ---------- | ----------------------------------------------------------------------------------------------- |
| `degraded` | staleness > 5× the reconcile interval, **or** ≥ 3 consecutive load failures                     |
| `error`    | staleness > 20× the interval, **or** the projection has never loaded (every app host is 503ing) |

Staleness is measured on a **monotonic** clock, so an NTP step can't flatter it; `lastSuccessAt` is
report-only.

The **`trust-proxy`** sub-check (`src/routing/trustProxyHealth.ts`, ADR-0011) watches the behaviour
the config guards can't: of the last 50 requests that arrived with `X-Forwarded-For` (the ring is
`TRUST_PROXY_WINDOW`), at least one must have resolved `req.ip` past the socket peer. It degrades
when none did — i.e. `EDGE_TRUST_PROXY` doesn't name the address the ingress actually presents and
every per-IP bucket (anon limiter, login throttle, audit hash) has collapsed to one per proxy:

| State      | When                                                                                                                    |
| ---------- | ----------------------------------------------------------------------------------------------------------------------- |
| `ok`       | fewer than 50 forwarded requests seen yet (`"not enough proxied traffic yet (n/N)"`), **or** ≥ 1 in the window resolved |
| `degraded` | the window is full of forwarded requests and **none** ever resolved                                                     |

Requests without the header never count — probes, `containerapp exec` and local dev satisfy
`req.ip === peer` correctly, so a quiet install stays green. The same gauge
(`helix.edge.trust_proxy.unresolved`) feeds the alert rule in `infra/azure/modules/alerts.bicep`.

> **`/health` answers 200 in every state, deliberately.** The body carries the degradation, never
> the status code. If you add a Container Apps liveness probe, do **not** point it at `/health`
> expecting a non-200 — a 503 here would restart replicas that are serving correctly from a stale
> copy, turning the serve-stale stance into the outage it exists to prevent. Nothing in
> `infra/azure` probes `/health` today.

**The log is also a metric channel.** Since ADR-0037 there is an OTel pipeline (see "Prefer the
metric" below), but the log events predate it, remain the detail an operator reads once an alert
fires, and are the only signal at all in a deployment with no OTLP endpoint configured — which is
still the platform's default state. `gateway_calls` is a metering primitive either way, not an
observability sink. So load failures
carry a stable `event` field for a log-based metric — the first failure at `error` level, one more
`error` when the copy crosses the 20× line, `warn` in between (~1 per reconcile interval), and one
`info` on recovery:

```jsonc
{ "level": 50, "event": "registry.load_failed", "consecutiveLoadFailures": 1, "staleForMs": 61234,
  "lastSuccessfulLoadAt": "2026-07-30T12:00:00.000Z", "reconcileIntervalMs": 60000,
  "msg": "registry projection load failed; serving stale" }
{ "level": 30, "event": "registry.load_recovered", "failures": 4, "staleForMs": 245678,
  "msg": "registry projection reloaded after 4 failed attempt(s)" }
```

A projection that has **never** loaded reports under its own event instead, because there is no age
to grade — `staleForMs` stays null forever, so the escalation is keyed on the failure count (which
tracks elapsed intervals when nothing succeeds). Every app host is 503ing in this state:

```jsonc
{
  "level": 50,
  "event": "registry.never_loaded",
  "consecutiveLoadFailures": 1,
  "staleForMs": null,
  "msg": "registry projection has never loaded; app hosts are serving 503",
}
```

Separately, **every** Postgres pool the edge builds reports a dropped client under one shared event,
so a single rule covers the fleet rather than one per pool. `phase` distinguishes a client that was
sitting in the pool from one a request had checked out (see "The two `'error'` windows" below):

```jsonc
{
  "level": 40,
  "event": "db.pool_client_error",
  "pool": "sessions",
  "phase": "checked-out",
  "msg": "pooled DB client dropped (sessions, checked-out)",
}
```

An alert rule over the Log Analytics workspace the environment already ships stdout to:

```kql
ContainerAppConsoleLogs_CL
| extend p = parse_json(Log_s)
| where tostring(p.event) in ("registry.load_failed", "registry.never_loaded")
| summarize maxStreak   = max(toint(p.consecutiveLoadFailures)),
            maxStaleSec = max(tolong(p.staleForMs)) / 1000
          by bin(TimeGenerated, 5m), tostring(p.event), ContainerAppName_s
```

**Prefer the metric.** Since ADR-0037 the edge also emits
`helix.registry.stale_for_ms` (an observable gauge — absent until the first successful load, so a
cold start reads as missing rather than as zero) and `helix.registry.load_failures{outcome}`. That
makes the alert **one threshold rule** rather than the KQL above, which is the reason it kept not
getting built. The query stays useful for the detail you read once the rule fires, and as the
fallback for a deployment with no OTLP endpoint configured.

**Both rules now exist** in `infra/azure/modules/alerts.bicep`: staleness reads the metric above,
and _never loaded_ reads the `registry.never_loaded` log event — because the gauge is deliberately
absent in that state and the counter that reports it is cumulative, so a threshold on it would
never stop firing (ADR-0037 Amendment 8). They are optional (`deployAlerts`) and notify a
parameterized address list; with none set they fire into nothing. `event` is a repo-wide
convention; see [`docs/design/logging.md`](../../docs/design/logging.md) before adding another.

**Note the verbose body is unauthenticated.** Any unrecognised `Host` classifies as `platform`, and
the auth host is internet-facing, so `lastSuccessAt` / `staleForSeconds` / `consecutiveLoadFailures`
are readable by anyone who can reach the edge. Accepted deliberately (ADR-0025): it is operational
metadata, not credentials, and gating it would break this polling workflow. Adding a field that
names apps or users would change that calculus.

### The two `'error'` windows on a Postgres pool

Worth knowing before touching `src/db/`: `pg-pool` gives a pooled client an `'error'` listener only
while it is **idle**, and strips it for the duration of a checkout. `pool.query()` covers its own
window; `pool.connect()` does not. Since `pg` emits `'error'` synchronously on a socket death but
defers the query rejection to `nextTick`, an unguarded checkout means a mid-transaction connection
drop kills the process before the awaited query ever rejects.

So `src/db/pool.ts` owns both halves — `createEdgePool` attaches the idle listener, and
`withPooledClient` is the **only** sanctioned `pool.connect()` (a `no-restricted-syntax` rule in
`eslint.config.mjs` enforces that). `withPartition` composes it, so every RLS-partitioned
transaction is covered. Reach for `withPooledClient` rather than checking a client out by hand.

## Dev workflow (in the dev container)

```bash
pnpm dev:idp        # :3002 — local OIDC issuer (apps/dev-idp; fixture users)
pnpm dev:portal     # :3001 — registry + deploy API
pnpm dev:edge       # :8080 — https (mkcert) with the real login flow;
                    #         EDGE_DEV_ALLOW_UNAUTHENTICATED=true additionally
                    #         skips the gate (the dev container sets it)

# Deploy + promote an example app (see packages/cli/README.md):
cd examples/hello-world
pnpm --filter @azx-pbc/helix-cli helix -- deploy --promote   # or: helix deploy --promote

# *.local.helix.azxlabs.io resolves to 127.0.0.1 (note: https now):
curl -ik https://hello-world.local.helix.azxlabs.io:8080/    # 302 → auth host (or 200 with the bypass)
curl -ik https://localhost:8080/health             # platform health JSON
```

To exercise the full login flow, unset the bypass for the edge process
(`EDGE_DEV_ALLOW_UNAUTHENTICATED= pnpm dev:edge`), open
`https://hello-world.local.helix.azxlabs.io:8080/` in a browser, and pick a fixture user
(`alice@azx.dev` / `bob@azx.dev` / `mallory@azx.dev`) on the dev IdP page. The
mkcert CA lives at `.devcontainer/certs/caroot/rootCA.pem` — import it into the
host trust store (`CAROOT=<repo>/.devcontainer/certs/caroot mkcert -install`,
then fully quit the browser) to silence browser warnings.

That import is optional for most work but **required to test the offline
capability**: a service worker needs a secure context, and clicking through the
certificate interstitial does not create one — the exception is per-tab UI state,
not a trust decision, so registration fails with _"An SSL certificate error
occurred when fetching the script."_

Archive via the portal API to see the 410 path:

```bash
curl -X POST -H "Authorization: Bearer $PORTAL_DEV_TOKEN" \
  http://localhost:3001/api/v1/apps/hello-world/archive
curl -ik https://hello-world.local.helix.azxlabs.io:8080/    # 410 + Clear-Site-Data
```

## Tests

Unit tests use in-memory fakes (`src/test/fakes.ts`), including a fake IdP and session store; the **adversarial suite** for the handoff path (replay, audience confusion, open redirect, cookie tossing, state/nonce tampering, expired/alg-confused tokens, session fixation) is `src/auth/adversarial.test.ts` plus `src/auth/handoff.test.ts`. Integration tests (`*.integration.test.ts`) run against the dev container's test Postgres (migrated by the vitest global setup) and Azurite, and boot an **in-process dev-idp on an ephemeral port** for the full Appendix A flow — including the concurrent-redeem race and a real `prompt=none` silent refresh.
