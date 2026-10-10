# Fetch proxy

> **Related ADRs:** [ADR-0005](../adr/0005-ssrf-egress-controls.md) (SSRF + secret injection) · [ADR-0013](../adr/0013-egress-trust-model.md) (egress trust model) · [ADR-0001](../adr/0001-three-runtime-split.md) (three-runtime split / edge posture) · [ADR-0014](../adr/0014-same-origin-api-gateway.md) (same-origin API gateway) · [ADR-0031](../adr/0031-connection-providers-delegated-auth.md) (connection providers — the delegated-auth catalog).

Apps call third-party APIs through a same-origin URL, for example
`fetch('/_api/fetch/https://api.github.com/...')`. The platform checks permissions,
meters and audits the call, applies SSRF controls, and injects a connection
credential when configured. Credentials stay out of the app. See architecture
§6.1 and `docs/design/fetch-proxy.md`.

| Route | Who | What |
| --- | --- | --- |
| `ALL /_api/fetch/<url>` | app host (edge) | authorize → mint instruction → forward to egress → stream back |
| `POST /proxy` | `helix-egress` (internal) | verify instruction → inject secret → SSRF controls → outbound call |
| `GET /_api/connections/:ref/status` | app host (edge) | the calling user's connection status for one bound provider (read-only) |

## How it works

The call crosses the policy/mechanism boundary (architecture §3): the edge
decides *whether* the call may happen and to *where*; egress actually makes it.

### The edge (policy plane)

`makeFetchHandler` (mirrors the LLM/data handlers):

1. **Gate.** `resolveCaller` — an authenticated session, or the anonymous caller
   on `public` apps (`ANON_USER_OID`). Anonymous callers also hit the per-IP
   limiter shared with the rest of `/_api/*`.
2. **CSRF.** `isSameOrigin` — the proxy call is same-origin by construction;
   anything else is `403`.
3. **Allowlist.** The target origin (parsed from the path raw *and*
   percent-decoded) must be a **proxied** origin in the app's manifest
   (`capabilities.fetch.origins`, projected as `proxyConnections`). Not present ⇒
   `403`, before anything leaves the edge. Direct-CSP origins
   (`externalOrigins`) are a separate list and are *not* proxied.
4. **Quota.** A per-app `requestsPerDay` budget (block-new/finish-in-flight),
   counted from `gateway_calls`.
5. **Concurrency cap (optional).** When `EDGE_FETCH_MAX_APP_IN_FLIGHT` is
   positive, the edge holds a Postgres lease on `fetch:app:<appId>` for the
   whole response (including a streamed body) and refuses over-cap calls with
   `429 rate_limited` before minting an instruction. `0` disables — no extra
   database round trip. Lease TTL is ten minutes; a call that outlives it stops
   counting (at most one residual slot per such call).
6. **Attest + forward.** The edge mints a short-lived signed instruction
   `(app, user, capability, origin, connection?, request-id)` and forwards the
   request + instruction to egress over the `EgressProvider` HTTP seam. The edge
   has **no grant on `app_secrets`** (it cannot read an app's connection secret)
   and no *arbitrary* outbound route — only egress reaches the open internet — so
   it can only ask egress to make a call it already authorized. The edge is *not*
   secretless, though: it holds its own operational keys (auth/instruction/OIDC)
   and today an over-broad Blob access key (tightening that to a read-only managed
   identity is tracked). (ADR-0001.)

### `helix-egress` (mechanism plane)

`POST /proxy` (`apps/egress/src/proxy.ts`) — the only component that touches
plaintext secrets or the public internet:

1. **Verify** the attested instruction (`jose`, HKDF key shared with the edge,
   `typ`-bound, 30 s TTL). Trusts it; never re-authenticates the user.
2. **Resolve + inject** the named connection secret, if any
   (`PgSecretResolver` under the `helix_egress` role; see
   `secrets-and-connections.md`). The credential is applied per its recipe
   (`Authorization: Bearer …`, a header template, or a query param). Both
   egress Postgres pools (this resolver and the instruction burn store) build
   through `createEgressPool` (`apps/egress/src/pool.ts`), which gives every
   query a Postgres-enforced `statement_timeout` (default 10 s,
   `EGRESS_STATEMENT_TIMEOUT_MS` to tune) so a stuck query can't pin a pooled
   connection on the plane that holds plaintext secrets, and attaches the
   idle-client `'error'` listener (ADR-0002 ISSUE-05).
3. **SSRF controls** (`apps/egress/src/ssrf.ts`): resolve every address and
   refuse private / loopback / link-local / `169.254.169.254` (IMDS), the Azure
   platform address `168.63.129.16`, and IPv4 documentation ranges (TEST-NET-1/2/3
   and the deprecated 6to4 relay anycast); pin the
   connection to the validated IP (cert/SNI still checked against the hostname),
   defeating DNS rebinding; no redirect-following (undici 7 only follows redirects
   when a `redirect` interceptor is composed onto the dispatcher, and egress
   composes none — a `302` to IMDS comes back as data, never chased, and its
   `Location` is stripped so the browser can't chase it either; issue #10).
4. **Header controls** — a **request-header safelist** (the app's
   `cookie`/`authorization` never go upstream: no session leak, no overriding the
   injected credential) plus a **response-header blocklist** (`set-cookie` and
   friends stripped off the response). The response blocklist has tracked gaps
   today — it omits `authorization`/`www-authenticate` (#7), the body caps read
   only `content-length` (#8), and the injection path still accepts cleartext
   `http://` (#11). (ADR-0005.)
5. **Stream** the upstream response straight back through the edge to the
   browser; never buffered.

### Metering

The **edge** writes one `gateway_calls` row per call (`capability = "fetch"`,
`model = <target origin>`, `path` + `method` for the request line, outcome mapped
from the egress outcome header) — it holds the ledger grant and owns audit.
Egress writes only `app_secrets.lastUsedAt`. The Audit/Usage pages light up for
`fetch` with no extra work.

The **allowlist denial is metered too**, as `outcome = "forbidden"` — an app
reaching for an origin its manifest never granted is the most audit-interesting
event on this surface, and it is the one outcome here that never reaches egress.
It is **rate-capped per (app, env)** (`DenialThrottle`): this is the one ledger
write no other gate bounds — the per-IP limiter skips authenticated callers, the
allowlist check returns before the quota gate, and the budget query excludes
`forbidden` — so without a cap a retry loop against a typo'd host appends to an
undeletable table at line rate. Past the cap the call is still refused; only the
metering is dropped, with a summary log line. The first rows carry the whole
audit signal. It does **not** count against `requestsPerDay`: that budget prices work done at
the egress boundary, and a denial mints no instruction and dials nothing, exactly
like `quota_blocked`. (Counting denials would not bound the ledger either — the
allowlist check returns *before* the quota gate, so a denial loop never reaches
it; counting would only starve the app's legitimate traffic.)

`path` is the target's **pathname only — the query string is not recorded**,
matching the line `redactFetchTarget` in `@azx-pbc/shared/logging` draws for
request logs. That is where credentials are conventionally placed (`?api_key=`, a
SAS `?sig=`).

**It does not follow that `path` is credential-free.** Some APIs put the secret in
a path segment (Telegram `/bot<TOKEN>/…`, Slack webhooks), and those are retained.
No heuristic tries to spot one: a token segment and a REST resource id are the
same shape, so any test that catches the former also eats `/customers/<uuid>/orders`
— the value this column exists to capture. The mitigations are bounding rather
than detection (truncation at write time, and the denial cap above), and
retention is the real fix. Read ADR-0021 for the full position, including the
asymmetry that matters most: log lines age out, ledger rows have no DELETE grant
for any role.

## Try it

The capability is enabled when both `EDGE_EGRESS_URL` and
`HELIX_INSTRUCTION_SECRET` are set (dev container: both are, and
`pnpm dev:egress` runs the service on `:8081`). Add a proxied origin in the
portal's **Capabilities → Fetch proxy** card (optionally bound to a connection
secret), approve it, then from the app:

```js
const r = await fetch("/_api/fetch/https://api.github.com/users/octocat");
const user = await r.json(); // proxied, audited; no CSP exception needed
```

## Transparent shim (zero-edit adoption)

For apps that set `capabilities.fetch.shim`, the edge builds a per-app script
(proxied origins baked in) and **inlines** it at the top of the document's
`<head>` at serve time (`apps/edge/src/serving/shim.ts`, wired from
`assets.ts`). It monkeypatches **both `window.fetch` and
`XMLHttpRequest.prototype.open`** — XHR too because `axios` defaults to the XHR
adapter — so an unmodified `fetch('https://api.github.com/…')` to a *granted*
origin is transparently rewritten to `/_api/fetch/…` with no code change. Inline
at the top of `<head>`, the patch lands before any app code captures `fetch`.

It used to be served from `/_helix/fetch-shim.js` and referenced with a
`<script src>`. That path is deliberately unprecachable by the offline
capability's service worker, so an app holding both grants lost the shim on
every offline cold boot — proxied calls then went direct and died on CSP rather
than failing as a proxy error (ADR-0035, amendment to §9). The route is gone.

It is **ergonomics, not a boundary**: it only ever adds reach the manifest
already granted (a rewrite to a non-allowlisted origin still 403s at the edge),
so deleting or bypassing it gains nothing — a direct call still dies on
`connect-src 'self'`. It fails safe. Toggle it in the portal's **Capabilities →
Fetch proxy** card.

## Delegated providers (per-user OAuth connections)

A proxied origin can bind an **OAuth connection provider** instead of a stored
secret. In the manifest, a `capabilities.fetch.origins` entry names `provider:
"<ref>"` — a provider the operator registered in the portal's catalog — as a
sibling of `connection` (the two are mutually exclusive: the manifest parse
refuses an origin with both, and an origin with neither is a keyless proxied
call):

```yaml
fetch:
  origins:
    - origin: https://app.acme.example
      provider: acme # the operator's catalog ref
      required: true # a dependency hint — see below
```

At call time, egress resolves **the calling user's own connection** to that
provider — the access token the user granted through OAuth consent, sealed
server-side and renewed automatically as it expires — and injects it into the
outbound request per the provider's token placement. The app never sees a
token; each user's calls carry that user's own grant. The token is issued only
to the provider's registered API destinations, and only over `https` (a
provider-bound call to a cleartext origin is refused `403 forbidden`). A user
with no connection to the provider gets an error — never someone else's
credential, never an unauthenticated call.

Consent is how a connection comes to exist, and it is **explicit, never
automatic**: the platform does not watch responses, does not open a popup when
a call fails, and does not retry anything. The app decides to offer a Connect
control, and calls one of the two entry paths below from inside it. Both paths
require a user gesture — that is the browser's popup rule, and the platform
never works around it.

### Entry path 1 — the connect helper (`window.helix.connect`)

Apps that grant `capabilities.shim.connect` get a `window.helix.connect()`
helper inlined into their HTML at serve time — the same injection discipline as
the fetch shim (opt-in, never unconditional; a provider binding alone never
injects it). It is a function, not UI, and has no automatic behavior: it does
not watch your `fetch` responses, does not open a popup on
`connection_required`, and does not retry anything.

```js
// inside the Connect button's click handler
const result = await window.helix.connect("acme"); // the provider ref
// { outcome: "connected", provider: "acme", attempt: "9f1c…" }
```

- It must be called inside a user gesture. Without one the browser refuses the
  popup and the result is `blocked`.
- It never throws and the promise never rejects — every flow result is an
  outcome.
- One popup per call. Concurrent calls for the same provider each get their own
  attempt and their own outcome (a losing concurrent saver reports
  `error`/`conflict`).

The result is `{ outcome, provider, attempt?, reason? }` — `attempt` is the
correlation tag (absent on `blocked`, where nothing was started), and `reason`
is present only with the `error` outcome. The outcomes:

| Outcome | What happened |
| --- | --- |
| `connected` | The user approved at the provider; the connection is saved. |
| `already_connected` | A working connection already existed — nothing was sent to the vendor. |
| `denied` | The user declined the provider's consent screen. |
| `cancelled` | The popup closed without completing. The helper acknowledges the cancellation so a late vendor completion cannot claim the attempt — and honestly: if the popup completed just before closing, the connection exists and your next call succeeds. |
| `timeout` | Five minutes elapsed with the popup open (the attempt expires server-side regardless). |
| `blocked` | The browser refused the popup (no user gesture, or a blocker). Control returns immediately; the platform never navigates the current tab and never retries the open. Offer Connect again. |
| `signin_required` | The caller has no usable app session. Sign in to the app, then Connect again. |
| `error` | A platform-side failure; `reason` names it: `conflict`, `provider_unavailable`, `provider_misconfigured`, `provider_incompatible`, `service_unavailable`. |

### Entry path 2 — the raw platform entry (no helper)

Without the shim grant, open the start route in a popup from a user gesture and
listen for the completion message yourself:

```
GET /_api/connections/:ref/start          optionally ?attempt=<correlation tag>
```

The start is a same-origin navigation on the app host — it runs the app's
session gates, so it must ride the app's own cookies; cross-site navigations
are refused. With a session, the popup is redirected straight to the provider's
consent screen. Every other outcome renders a platform page that posts the
outcome message (below) before offering Close.

On the dev tier the entry is a POST — the dev token must never ride a popup
URL: `POST /<slug>/_api/connections/:ref/start` with the bearer token answers
`{outcome: "started", popupUrl}` (open the returned single-use URL on the auth
host), or a terminal `already_connected` / `not_available`.

**The completion message.** Every platform page in the popup posts one message
to its opener before closing:

```json
{
  "source": "helix-connect",
  "version": 1,
  "attempt": "9f1c…",
  "provider": "acme",
  "outcome": "connected",
  "reason": null
}
```

`attempt` is your correlation tag, echoed when the sender knows it (the
start-route pages echo it; the auth-host completion pages do not) — present
only when the start URL carried one. `outcome` uses the same vocabulary as the
helper's result; `reason` is `null` unless the outcome is `error`.

**Verify a message before trusting it** — a message is a notification, never
an authorization grant (it carries no token), and any window on the web can
`postMessage` at yours:

1. the sender (`event.source`) is the popup you opened;
2. `event.origin` is one of the platform origins that may message you — the
   app's own host (start-route pages) or the auth host (completion pages, and
   every page of the dev journey);
3. the shape parses: `source` is `"helix-connect"`, `version` is `1`,
   `provider` matches the ref you are connecting, `outcome` is in the set,
   `reason` is `null` unless the outcome is `error`, and `attempt` — when the
   message carries one — matches the tag you put on the start URL.

Discard everything else. The helper implements exactly these checks; an app on
the raw entry must too.

### The connection-status check

An app that wants to shape its UI around connection state — show Connect up
front, or distinguish "sign in first" from "connect Asana" — can ask without
firing a real provider-bound call or opening a popup:

```
GET /_api/connections/:ref/status          (app host, the session's cookie)
GET /:slug/_api/connections/:ref/status    (dev tier, the bearer dev token)
```

The answer is JSON, one key: `{"status": "connected"}`, `{"status":
"not_connected"}`, or `{"status": "not_available"}`. The three words are
exactly what the next provider-bound call would say:

- `connected` — a live connection row; the next delegated call dispatches
  (a dead token still reads `connected` — renewal runs invisibly at call
  time, or fails there with the mapped error).
- `not_connected` — the binding is effective and the provider configured, but
  the caller holds no working connection: never connected, reconnect-needed,
  invalidated, or a dead token, indistinguishably. The remedy for all of them
  is the same Connect control.
- `not_available` — one of the consult's own gates would refuse: the app is
  unknown, the manifest does not effectively bind the ref (never approved, or
  stale-dated by a sensitive provider edit), or the provider row is missing
  in the caller's tier. Connect would fail too — this is the app's (or an
  administrator's) problem to fix, not the user's.

The read is session-gated: a signed-out caller — including a pseudonym or an
anonymous visitor, who can never hold a connection — gets `401` and should be
shown sign-in, not Connect. A malformed ref is `404` (a probe, not a state);
an unconfigured portal seam or a failed internal hop is `503`, fail-closed.

Two honesty rules, the same ones My Connections holds. The status is **Helix's
own row state** — it never claims to have verified the vendor-side grant, and
no vendor is contacted. And it answers **only for a provider the app's
effective manifest binds**: an app cannot probe whether its users have
connections to providers it does not use.

The read writes nothing — no consent attempt, no state change — so it is safe
to call on page load. It is a read, not a decision: the platform still never
opens a popup, watches responses, or retries on its own, and after any
outcome the app decides what to offer next.

### Delegated-call errors

When a provider-bound call cannot be served, the proxy answers JSON instead of
an upstream response — `{code, message, provider?}`. Every `message` is a fixed
platform string: never vendor error text, never credential material, never
internal detail. As shipped:

| Situation | HTTP | `code` | Body | Ledger outcome |
| --- | --- | --- | --- | --- |
| The caller has no usable connection to the bound provider — never connected, the user declined the vendor's consent, the token is dead or invalidated, a renewal ended in an uncertain rotation or an explicit permission loss, the user disconnected elsewhere, or the caller's kind can never hold a connection | 403 | `connection_required` | `provider: {ref, displayName?}` | `connection_required` |
| The provider was deleted, or the binding is blocked by a sensitive provider edit (the connection was invalidated; the origin is no longer one of the provider's API destinations) | 503 | `provider_unavailable` | `provider: {ref}` | `refusal` |
| The provider's configuration is invalid (malformed row, or renewal reported the provider's credentials rejected) | 502 | `provider_misconfigured` | — | `refusal` |
| Temporary renewal failure / vendor outage — the connection is preserved | 502 | `upstream_error` | — | `error` |
| The origin was never granted for this app (the binding was never approved) | 403 | `forbidden` | — | `forbidden` |

`connection_required` carries `provider.ref` — and `displayName` when the
platform can name the provider — so the app can offer Connect for exactly that
provider. It is also a distinct `gateway_calls` outcome label: the Usage and
Audit pages separate "the user was not connected" from "policy refused", which
is what the other provider-shaped codes deliberately do not do (they meter as
the existing `refusal`).

### What the user can fix, and how

Every outcome above is either something the user can remedy by connecting, or
something only an administrator can. The remedy for every connection-shaped
failure is the same control the app already offers:

- **No connection yet, `denied`, dead or invalidated token, reconnection
  required (an uncertain rotation or a permission loss), disconnected by the
  user in the portal** — offer Connect again. Re-consenting replaces the stale
  state; a `reconnect-needed` or invalidated row is replaceable through consent.
  If Connect answers `already_connected`, the connection had landed after all —
  re-issue the call.
- **`error`/`conflict` from a concurrent connect** — the same user's other
  Connect for this provider finished first, so the connection already exists;
  re-issue the call.
- **`signin_required`** — the user signs in to the app, then Connect again.
  **For anonymous visitors (public apps) and shared-password pseudonyms there
  is nothing to sign in as, and `connection_required` is unremediable for that
  identity** — those callers can never hold a delegated connection, no matter
  how many times they connect. An app whose audience includes them should not
  offer Connect at all.
- **`provider_unavailable`, `provider_misconfigured`** — not user-remediable.
  An administrator restores or fixes the provider, the app's owner re-saves the
  binding for re-approval if it changed, and then the user connects again.
- **`upstream_error`** — temporary; the connection is preserved. A later call
  may simply succeed.

Users see and manage their own connections in the portal's **My Connections**
page — per-provider status (`Connected` / `Reconnect needed`) and disconnect.
A disconnect there is what makes the next API call answer
`connection_required`.

**Retry is the app's decision.** After any of these outcomes, the app decides
whether and when to try again — the platform never replays a call, not after a
consent error and not after an upstream failure. The typical loop: on
`connection_required`, offer Connect; on a `connected` or `already_connected`
outcome, re-issue the call that failed.

### `required` is a dependency hint, nothing more

`required: true` on a provider-bound origin documents that the app depends on
that connection. That is all it is — a hint for reviewers and the portal UI. It
never blocks the app from loading, never triggers a popup, never gates a call,
and never runs a check platform-side. An unmet `required` binding behaves
exactly like the error table above — the call answers `connection_required`,
and the app decides what to show.

### The Connect control is app-authored — accessibility included

The platform injects no UI into your app, so the Connect control is yours to
build well:

- **A visible label naming the provider** ("Connect to …"), on a **real
  `<button>`** — keyboard-reachable, announced by assistive tech, not a
  click-handled `<div>`.
- **Focus stays on the control through the popup cycle.** Opening the popup
  never navigates the app's own tab, and the helper resolves in place — so keep
  focus where the user left it and surface the outcome there: update the
  control's label/state and announce it (a polite live region, or focus the
  control), rather than replacing the page or stealing focus with a modal.

## Key files

- `apps/edge/src/gateway/fetch.ts` — `makeFetchHandler`, the policy plane.
- `apps/edge/src/routing/connectionStatus.ts` — the app-facing connection-status read.
- `apps/edge/src/serving/shim.ts` + `assets.ts` — the shim script + serve-time injection.
- `apps/edge/src/serving/connectHelper.ts` — the `window.helix.connect` helper script.
- `apps/edge/src/routing/consentStart.ts` — the raw consent entry route + its terminal pages.
- `apps/edge/src/gateway/instruction.ts` — mints the attested instruction.
- `apps/egress/src/{proxy,ssrf,instruction}.ts` — the mechanism plane: verify, inject, SSRF, stream.
- `apps/egress/src/delegated.ts` — delegated-call resolution: the caller's connection, renewal, and the error taxonomy.
- `packages/shared/src/{instruction,manifest}.ts` — the instruction payload + `capabilities.fetch` schema.
- `packages/shared/src/consent.ts` — the completion-message and helper-result contracts.

## Design notes (the why)

- **Why a separate plane, not a forked process.** Secret injection breaks the
  password pattern's containment: a password projects only a *hash* (the edge
  verifies, never recovers it), but a connection secret must be injected as
  *plaintext* into an outbound header — "you can't inject a hash." The boundary
  that matters is a separate deployable unit with its **own** managed identity
  (authenticates to Key Vault as itself) and **own** network zone — a forked
  process shares both and "buys you almost nothing." The split buys three things:
  credential isolation that is true-by-architecture not by-code-review;
  **network/SSRF isolation** (the big one — the edge has no *arbitrary* outbound
  route, only egress reaches the open internet, so an SSRF bug in the edge itself
  reaches nothing; ADR-0001); and dependency
  isolation (the fat HTTP deps live on egress, the edge stays minimal §3). Honest
  limit: extraction *relocates* the all-secrets read, it doesn't eliminate it —
  egress still holds the vault grant.
- **Attested instruction, not re-auth.** Egress trusts the edge's signed
  attestation and never re-authenticates the user, so a compromised egress can't
  become an identity-forging service — it can only act on what the edge already
  attested. The instruction reuses the OIDC-handoff primitives (`jose` + HKDF off
  `HELIX_INSTRUCTION_SECRET`), domain-separated by a distinct `typ` and HKDF info
  string, carrying `(app, user, capability, origin, connection?, request-id)`
  with a 30 s TTL. It now also carries `aud: "azx-egress"` and a `jti` (= the
  request-id), **burned one-time at egress** so a captured instruction can't be
  replayed within its TTL (ADR-0013 Step 1, issue #3 — `apps/egress/src/burn.ts`,
  shared `instruction_jti` table). **This seam still does not contain an *edge*
  compromise:** the instruction is signed with a **symmetric secret both planes
  hold**, so a compromised edge can forge an instruction for any `appId`, and
  `method`/`path` are still unbound. The edge cannot *read* `app_secrets`
  directly (no DB grant), but it can steer egress to spend a connection.
  Remaining hardening is tracked: per-action authz + method/path binding before
  multi-tenant (#6), asymmetric (Ed25519) signing post-M5 (ADR-0013). A header
  today; the shape is forward-compatible with an mTLS/SPIFFE SVID later.
- **The adoption spine** is three rungs that never fork the mental model: (1) the
  path-prefix wire contract `fetch('/_api/fetch/https://…')` — a mechanical
  string prefix that is codemod-able (a POST-envelope design was rejected because
  it forces a full rewrite); (2) the opt-in shim above; (3) CSP-origin grants and
  the fetch proxy as "one knob, two settings" (`mode: direct|proxy`). Shim scope
  is **HTTP request/response only** — out of scope by design: WebSocket,
  EventSource/SSE, and `<img>`/`<form>`/font loads.
- **SSRF gotchas.** `undici.request` (v7) follows a redirect only if a `redirect`
  interceptor is composed onto the dispatcher; egress composes none, so a `302` to
  IMDS is returned as data, never chased — and `Location` is stripped from the
  response so the browser can't follow it un-proxied either (issue #10).
  `URL.hostname` keeps IPv6
  brackets (`[::1]`) which `isIP` rejects — they're stripped before resolve. The
  whole host is refused if *any* resolved address is blocked (defeats a
  dual-A-record split), and the connection is pinned to the validated IP against
  rebind. App-layer checks here are the belt; an NSG/firewall is the
  network-layer suspenders in prod.

## Planned / not yet built

- **Egress byte metering** — `gateway_calls` records the call + outcome; request/
  response byte counts are not yet tallied.
- **Stronger egress isolation** (per-tenant egress, microVM) lands only when
  *untrusted* code runs in the egress path (custom backends); shared egress is
  fine while the egress code is ours — design §10.
