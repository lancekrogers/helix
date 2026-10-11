# Edge serving

> **Related ADRs:** [ADR-0017](../adr/0017-registry-listen-notify-projection.md) (registry projection) · [ADR-0025](../adr/0025-registry-projection-hardening.md) (projection hardening) · [ADR-0009](../adr/0009-relaxed-csp.md) (relaxed CSP) · [ADR-0019](../adr/0019-subdomain-per-app-isolation.md) (subdomain isolation) · [ADR-0020](../adr/0020-static-only-apps-v1.md) (static-only apps) · [ADR-0003](../adr/0003-dependency-minimal-edge.md) (dependency-minimal edge) · [ADR-0002](../adr/0002-postgres-role-split-rls.md) (Postgres role split) · [ADR-0001](../adr/0001-three-runtime-split.md) (three-runtime split) · [ADR-0028](../adr/0028-deployment-model-customer-deployed.md) (per-install domain split).

The edge (`apps/edge`) routes requests by hostname, authenticates app users,
streams assets from Blob, and applies the platform CSP. Missing and archived
apps receive consistent 404/410 responses. The service is stateless and uses
parameterized SQL and HTTP clients instead of an ORM or vendor SDKs. New runtime
dependencies require justification (project plan §1).

See [`apps/edge/README.md`](../../apps/edge/README.md) for the full request flow and config.

## How it works

### Host classification (the two-router discipline)

Every request is classified **once** at an `onRequest` hook into `app` / `legacy-app` / `auth` /
`platform`, and the two worlds never mix — platform handlers are unreachable on app hosts and vice
versa (architecture §3, decision 12). `apps/edge/src/app.ts` decorates `req.hostClass`;
`apps/edge/src/routing/hosts.ts` does the parsing via `classifyHost(host, baseDomain,
controlDomain, legacyAppRedirect)`. Reserved subdomains (`auth`, `portal`, `api`, `www`) are
protected under the apps suffix; in split layout `auth.<appsDomain>` is platform, not auth. An
unmatched slug falls through to `platform`.

When `EDGE_LEGACY_APP_REDIRECT` is on in a split install, `legacy-app` hosts run a GET/HEAD-only
307 to the same path on the apps domain (`routing/legacyRedirect.ts`), with `Cache-Control:
no-store` and the `helix.edge.legacy_app_redirects` counter (`outcome` dimension). Paths starting
with `_` are never redirected. `publicOrigin` refuses reserved labels so app URL builders cannot
silently emit control-host origins.

| Setting | Default | Failure direction |
| --- | --- | --- |
| `EDGE_CONTROL_DOMAIN` | unset → `EDGE_BASE_DOMAIN` | Unset or blank: single-domain layout. Control domain under the apps domain or invalid hostname: edge refuses to boot |
| `EDGE_LEGACY_APP_REDIRECT` | off | Off: old app hosts on the control domain 404. On (split only): 307 for live apps. Ignored without a split |

A consequence worth knowing: `/health` returns the platform health JSON on platform/auth hosts,
but on an app host it serves the app's own `/health` file (or the SPA fallback) — see
`apps/edge/src/app.ts:161`. Likewise `/start`, `/callback`, `/_auth/*`, `/_api/*` are real
endpoints on the auth/app hosts but just asset paths an app may ship on its own.

### Registry projection (LISTEN/NOTIFY)

The edge never queries the registry per request. It holds an **in-memory slug → entry map**
loaded with hand-written SQL from `apps` + `versions`, and refreshes it on Postgres
`LISTEN/NOTIFY` (debounced ~100 ms) with a reconcile reload every ~60 s (±20% jitter, so replicas
don't herd the DB on one tick) as a safety net.

- `apps/edge/src/registry/projection.ts` — the map + loader. Parses `capabilities` JSONB
  fail-closed (`llm`/`data` → null on bad data). Serves the previous copy on a load error
  (fail-static, never fail-open), and tracks load freshness (`freshness()`).
- `apps/edge/src/registry/listener.ts` — the LISTEN connection with exponential-backoff
  reconnect, the jittered reconcile chain, and the load-failure log escalation.
- `apps/edge/src/registry/health.ts` — the staleness thresholds that turn `freshness()` into the
  `/health` sub-check.

The projection is read-only by DB grant (see [authentication.md](./authentication.md) and the
role split below) — the edge cannot write the registry.

> **Staleness caveat (ADR-0025).** Fail-static is not free: on a *sustained* DB failure the
> projection keeps serving its last-loaded copy, so a reduce-visibility or archive change may not
> take effect. That behaviour is deliberate; what is closed is the **silently** part. Every load
> updates `RegistryProjection.freshness()` (monotonic age + a consecutive-failure counter), and
> `/health` on platform/auth hosts now carries a `registry-projection` sub-check that reports
> `degraded` past 5× the reconcile interval or 3 consecutive failures, and `error` past 20× or when
> the projection has never loaded. The first failure logs at `error` level with a stable
> `event: "registry.load_failed"` field (the counter rides along; recovery logs
> `registry.load_recovered`), which is what a Log Analytics alert rule keys on — see
> [`apps/edge/README.md`](../../apps/edge/README.md#health-and-staleness).
>
> **`/health` still answers 200 in every state.** The body carries the degradation, never the
> status code: a non-200 would let a liveness probe restart a replica that is serving correctly
> from a stale copy — fail-static turned into the outage it exists to prevent.

### Blob asset streaming

Assets are **streamed, never buffered**, directly from Blob using undici with a hand-rolled
Azure SharedKey signature (no Azure SDK).

- `apps/edge/src/blob/client.ts` — undici pool reader, signed GET/HEAD.
- `apps/edge/src/blob/signing.ts` — the Azure SharedKey HMAC-SHA256 canonical string. Note this
  means the edge today holds the **full read/write/delete** Blob account key, even though a
  read-only managed identity is already provisioned — tightening to it is a P0 (ADR-0001, issue
  #15). This is why the edge is **not** secretless: it has no grant on app connection secrets, but
  it does carry its own operational keys and this over-broad Blob key.
- `apps/edge/src/serving/assets.ts` — the asset handler: runs the session gate, composes
  `{version.blobPrefix}{relPath}`, sets cache headers, injects CSP, and does the SPA fallback.
- `apps/edge/src/serving/paths.ts` — path-traversal defense (reject `..`, backslashes, NULs;
  pre- and post-percent-decode).

Behaviors to know:

- **SPA fallback** — an HTML-accepting miss serves `index.html` (deep links work); a non-HTML
  miss stays a hard 404.
- **Cache headers** — HTML is `Cache-Control: no-cache` (pointer flips are visible immediately);
  other assets get `private, max-age=300` with ETag/304.
- **App-supplied service workers are refused** — a request with `Service-Worker: script` gets a
  `403`, so an app can't register a SW that observes the handoff token on `/_auth/complete`.
  Plain web workers are allowed (`worker-src 'self' blob:`), and a `blob:` URL can never register
  a service worker in the first place.
- **The offline capability** ([ADR-0035](../adr/0035-offline-capability-platform-service-worker.md))
  is the one exception, and it registers *platform* code, not the app's. An app declaring
  `capabilities.offline: { scope: /app/ }` gets:
  - `GET /_helix/sw.js?scope=<scope>` — the platform worker, **ungated** (a gated update check
    would 302 an expired session to the auth host, and a redirect during a worker script fetch is
    a spec error, which would silently strand a revoked worker). Served `no-cache`, carrying the
    app's CSP (for a worker, the policy on the script governs the worker's own `fetch()`), and
    with `Service-Worker-Allowed: <scope>` — **the only response on the platform that carries that
    header**. The cache is keyed to the live version's `blobPrefix`, so a promote or rollback
    rotates it; documents are network-first, so an online client always gets the live version.
  - **Why the scope is in the URL.** The max-scope check runs on every *update* check, not just at
    registration: the browser re-reads `Service-Worker-Allowed` from each script response, and
    absent it the maximum scope is the script's own directory (`/_helix/`), which a `/app/`
    registration fails with a `SecurityError`. The tombstone below is served precisely when the
    grant is gone and there is no scope left to look up, so the URL has to carry it. The value is
    echoed into the header only after passing the same validator the manifest field does, and the
    real worker is served only when it matches the granted scope — so the parameter cannot buy a
    working worker at an arbitrary prefix without passing the approval gate.
  - The page-side registration, **inlined into `<head>`** at serve time like the fetch shim, so
    adopting the capability is a manifest change and nothing else. It is not a route: it used to be
    served from `/_helix/sw-register.js`, but `/_helix/*` is exactly what the worker never caches,
    so a `<script src>` there could not load on an offline cold boot. `/_helix/sw.js` is the only
    script route left under the prefix — a worker script has to be a URL — and every other
    `/_helix/` path 404s.
  - No grant, archived, or unknown slug ⇒ `/_helix/sw.js` answers with a **self-unregistering
    tombstone** rather than a 404, because browsers differ on whether a 404 during an update check
    unregisters or merely fails the update.
  - The worker route **503s when the registry projection has not loaded**, and a granted app mid-promote
    (no live version yet) 503s too. Serving a tombstone is destructive and irreversible
    client-side, so a DB blip during a fleet restart must not be allowed to wipe offline support
    across every device; a failed update check leaves the working worker installed.
  - The scope is validated on write *and* re-validated in the projection: never root, never a
    `_`-prefixed namespace, so the worker provably cannot reach `/_auth/*` or `/_api/*`.
- **Scope-aware SPA fallback** — an offline app is served from its scope prefix and its bundle
  nests under that prefix, so an HTML miss *inside* the scope falls back to `{scope}index.html`
  rather than the bundle root. A miss outside the scope keeps the root behaviour. A scoped app's
  bare `/` therefore 404s unless it ships its own root `index.html`; the platform deliberately does
  not redirect (that would make the edge care about an app's internal layout).

### CSP injection (§4.4)

`apps/edge/src/serving/csp.ts` sets the policy on **every** app response (not just HTML — SVG/
XML can execute script). The split:

- **Strict / data-flow** (containment): `connect-src 'self'` (the gateway is same-origin at
  `/_api/*`), `form-action 'self'`, `frame-ancestors 'none'`, `base-uri 'self'`.
- **Relaxed / code-provenance** (vibe-coded apps inline/eval freely): `script-src`/`style-src`
  with `'unsafe-inline' 'unsafe-eval'` + a curated CDN allowlist (cdnjs, jsDelivr, unpkg, esm.sh,
  tailwind, Google Fonts).
- **Image / plugin containment:** enforced `img-src 'self' data: blob:` plus approved origins and
  operator `EDGE_IMG_SRC_EXTRA`; `object-src 'none'`. Top-level navigation, popups/`window.open`,
  approved origins, request URLs to permitted CDN hosts (Hypothesis), WebRTC, and DNS
  prefetch/preconnect hints remain open (WebRTC and DNS-hint behavior under this policy is
  untested). The platform does not claim confidentiality against a hostile app author.

An app's approved `externalOrigins` (from its manifest, gated through the approvals
write-gate) extend `connect-src` (`https:` and `wss:`) and `img-src` (`https:` only). Origins are
reduced to bare CSP sources (`new URL().origin` — scheme+host+port, path stripped); wildcard hosts,
non-`https`/`wss` schemes for `connect-src`, and hostnames outside `[a-z0-9.-]` (aside from IPv6) are
dropped fail-closed. A same-origin `report-uri /_csp-report` funnels violations to the edge sink.
The sink caps stored reports at 100 INSERTs per app per 10-minute window (`CSP_REPORT_INSERT_MAX` /
`CSP_REPORT_INSERT_WINDOW_MS` in `apps/edge/src/serving/cspReportThrottle.ts`); additional reports
are counted on `helix.edge.csp_reports` with `helix.outcome=dropped` but not persisted. The portal
**Violations** screen (`GET /api/v1/csp/violations`) aggregates the last 30 days
(`CSP_VIOLATIONS_LOOKBACK_DAYS`). A report's `blockedUri` can carry the data a page tried to send
out; admins see it when reviewing violations.

Per-install settings: `EDGE_IMG_SRC_EXTRA` (operator-trusted image hosts, never an image proxy),
`EDGE_IMG_SRC_ALLOW_ALL` (restores `img-src https: data: blob:` on the enforced header while keeping
`object-src 'none'`), and `EDGE_IMG_SRC_REPORT_ONLY` (measurement window: the previous open policy
enforced and the tightened one as Report-Only, until the operator enforces).

### Transparent fetch shim (serve-time HTML inlining)

The fetch-proxy contract is a path prefix: app code calls `fetch('/_api/fetch/https://…')`,
a same-origin call the CSP permits, which the edge authorizes and forwards to helix-egress (see
[fetch-proxy.md](./fetch-proxy.md)). The shim is the **zero-edit adoption path** on top of that
contract — for apps that opt in via `capabilities.fetch.shim`, the edge inlines a tiny per-app
script into the document that monkeypatches `window.fetch` **and** `XMLHttpRequest.prototype.open` (both, because
axios defaults to XHR) so a call to a granted proxied origin is transparently rewritten to the
same-origin `/_api/fetch/…` path. No app code changes.

- `apps/edge/src/serving/shim.ts` — `buildShimScript(origins)` bakes this app's proxied origins
  into the script (only granted origins are rewritten; a non-granted rewrite would 403 anyway);
  `injectHeadScripts(html, scripts)` inserts each one **inline**, right after the first `<head>`,
  so they run before any app script captures `fetch`. It composes: an app holding both
  `fetch.shim` and `offline` gets the shim first, then the worker registration.
- **Inline, not `<script src>`.** The shim used to be served from `/_helix/fetch-shim.js`, but
  `/_helix/*` is deliberately unprecachable (the same rule that keeps `/_api/*` usable as a
  reachability probe), so on an offline cold boot the tag could not load: `fetch` stayed
  unpatched, proxied calls went direct and died on CSP, and the parser-blocking tag cost a network
  timeout before first paint. That route and `/_helix/sw-register.js` are both gone — those paths
  404 through `isReservedAppPath`, which still reserves `/_helix/*` alongside `/_auth/*` and
  `/_api/*`. Two consequences worth knowing: `'unsafe-inline'` in `script-src` is now load-bearing
  for the platform (never add a hash or nonce — under CSP3 either one *disables*
  `'unsafe-inline'`), and every interpolation into an inlined snippet goes through `jsonInline` so
  a manifest-derived origin cannot close the `<script>` block. A `//# sourceURL=helix/…` comment
  keeps each snippet a named file in devtools.
- **Injection forces a full body and drops the etag.** For an opt-in app's HTML, `assets.ts`
  suppresses the `If-None-Match` (a `304` would skip injection), buffers the one HTML doc, inlines
  the scripts, and sends it with no `etag`/`last-modified` — the injected bytes differ from Blob's,
  so a conditional `304` must never short-circuit injection. Every other asset keeps streaming.

It is **ergonomics, not a boundary**: delete or bypass it and you gain nothing — a direct call
to a non-granted origin still dies on `connect-src 'self'`. It fails safe. Out of scope (it is an
HTTP request/response proxy): WebSocket, EventSource/SSE, `<img>`/`<form>`/font loads.

### 404 / 410 semantics

- **404** — unknown slug, no live version, rejected path, and missing asset all answer the
  same way (plain text, `Cache-Control: no-store`), so the registry isn't enumerable.
- **410 Gone** — an archived app, checked before the session gate, returns `410` with
  `Clear-Site-Data: "cache", "storage"` to evict cached UI and storage.

`apps/edge/src/errors.ts` holds the 403/404/410 responders.

### DB role split (containment)

The edge connects as the least-privilege `helix_edge` role: `SELECT` on `apps`/`versions`
(the projection), `SELECT`+`INSERT` on `gateway_calls` (metering), `INSERT`-only on
`app_collection_items` (write-only collections), and RLS-partitioned access to `app_data`.
It cannot write the registry, run DDL, or read collections. An edge RCE is contained to that
footprint. Asserted in `apps/edge/src/registry/role-split.integration.test.ts`; grants live in
the portal migration `20260616000001_edge_role_grants` (see
[app-data-gateway.md](./app-data-gateway.md)).

> **Role caveat (ADR-0002).** `helix_edge` is real and tested. In **production** the edge now
> **boot-fails** unless `EDGE_DATABASE_URL` (the least-privilege role) is set — it refuses to fall
> back to the owner `DATABASE_URL`, which would bypass RLS and silently defeat the split. Outside
> production the owner-DSN fallback remains, as a convenience for setups without the role split.
> The portal now follows the same pattern: it connects as `helix_portal` via `PORTAL_DATABASE_URL`,
> required in production with the owner-DSN fallback refused (ADR-0002).

## Planned / not yet built

- **Production TLS** terminates at ingress; in dev the edge terminates TLS itself with mkcert
  (the platform is HTTPS-only — it refuses to boot without TLS, because `__Host-` cookies need
  `Secure` and app crypto APIs need a secure context).
- **Azure Blob** in production; dev uses Azurite. The signing/stream path is provider-shaped
  already.
- _(Since shipped: the real Entra app registration and the Azure deploy both landed — the edge
  now serves on the wildcard apps domain in production.)_

Visibility at serving is fully wired: `public` apps short-circuit the gate (served to everyone,
no session), `password` apps route through the gate to their own same-origin `/_auth/login`
challenge, and every other mode stays behind the OIDC session gate (see
[authentication.md](./authentication.md)).
