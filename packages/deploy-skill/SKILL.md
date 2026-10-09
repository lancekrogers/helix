---
name: helix-app
description: Build and deploy a web app on the Helix app platform. Use when writing, changing, or deploying an app that will be hosted on Helix — covers the static-frontend constraint, the capability manifest, the /_api/* gateway (LLM, app data, fetch-proxy), the Content-Security-Policy you must build within, and the deploy/promote flow via the helix CLI.
---

# Building an app on Helix

Helix hosts vibe-coded web apps behind SSO. Its whole design assumes **your app is
untrusted code**, so the platform contains it rather than reviewing it. That single
stance explains every rule below — read it once before writing any code, because
several of these constraints are the kind you cannot retrofit.

This deployment:

- **Portal** (control plane — API and UI): `{{PORTAL_ORIGIN}}`
- **Your app**, once deployed: `https://<slug>.{{APPS_HOST}}`
<!-- IF:DEV_API -->
- **Dev gateway** (build it from somewhere else first): `{{DEV_API_BASE}}/<slug>`
<!-- /IF:DEV_API -->

---

## 1. The hard constraints

**An app is a static frontend. There is no server code.** You ship HTML, CSS, JS,
and assets. There is no place to run a backend, no environment variables, no
secrets in your bundle, no build step on the platform. Anything dynamic — calling
a model, storing data, reaching a third-party API — goes through the platform's
**same-origin gateway at `/_api/*`**, which the edge serves on your app's own
origin. You never hold an API key.

**Every response carries a strict Content-Security-Policy.** The one that will bite
you is `connect-src 'self'`: your app **cannot `fetch()` a third-party origin
directly**. Two ways out, both requiring a grant in the manifest (§2):

- Route the call through the platform: `fetch('/_api/fetch/https://api.example.com/thing')`.
  This is the good path — audited, metered, SSRF-controlled, and it can inject a
  stored credential server-side so no key ever reaches the browser.
- Ask an admin to widen CSP for a direct browser call (`externalOrigins`). Only
  sensible for public, keyless, CORS-enabled APIs.

The full policy applied to every app response:

```
default-src 'self';
script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' <CDNs>;
style-src  'self' 'unsafe-inline' https://fonts.googleapis.com <CDNs>;
font-src   'self' data: https://fonts.gstatic.com <CDNs>;
img-src    https: data: blob:;
media-src  'self' data: blob:;
connect-src 'self';
worker-src 'self' blob:;
form-action 'self'; frame-ancestors 'none'; base-uri 'self';
report-uri /_csp-report
```

`<CDNs>` is `cdnjs.cloudflare.com`, `cdn.jsdelivr.net`, `unpkg.com`, `esm.sh`,
`cdn.tailwindcss.com` — those load without a grant. Approved origins are appended
to `img-src` and `connect-src`.

**Other serving rules.** Do not ship a service worker — one you register is
refused (`403` on a `Service-Worker: script` request). Plain web workers are
fine. If the app needs to work with no network, ask for the **offline**
capability instead (below); the platform supplies the worker. A request that
accepts HTML and matches no asset falls back to `index.html`, so client-side
routing works. HTML is served `no-cache`; other assets get a short private cache
with ETags. The path prefixes `/_api/*`, `/_auth/*`, and `/_helix/*` are reserved
by the platform — do not route on them.

**Offline (cold boot with no network).** Declare it in the manifest:

```yaml
offline:
  scope: /app/
```

The platform then serves its own service worker confined to that prefix and
injects the registration — **write no worker code and no `register()` call**. It
must not be the domain root or a `/_…` path.

Two things this changes about your build, and the second is where people trip:

- Serve the app from the scope. Set your bundler's base path to `/app/`.
- **Nest the output under that directory too.** A URL path maps directly onto a
  stored file, so `/app/main.js` reads `app/main.js` from your bundle — with Vite
  that is `base: "./"` plus `build.outDir: "dist/app"`. Setting the base alone
  produces URLs that look correct and all 404.

The bare domain then 404s unless you ship a root `index.html` redirecting into
the scope — the platform will not do it for you. Also add a web app manifest with
`start_url: /app/`, since offline entry from the bare domain is not possible:

```html
<link rel="manifest" href="./manifest.webmanifest" crossorigin="use-credentials" />
```

**`crossorigin="use-credentials"` is required on any app that is not `public`.**
Browsers fetch a web app manifest with credentials omitted, so without it the
request carries no session cookie, the edge answers `401`, and the app is
silently not installable — everything else looks fine. This is the single most
likely thing to go wrong when you add a manifest.

What the grant buys is **cold boot only**: the document and its static assets
answer with no network. Everything else is still yours and needs no grant —
handling `/_api/*` failures, IndexedDB or `localStorage` for durable state,
`caches.open()` for large payloads, and draining queued work when the connection
returns. `GET /_api/me` is the reachability probe: it is root-level, so it can
never be answered from cache. See the `offline` example app.

**The transparent fetch shim works offline too.** Both platform snippets — the
shim and the worker registration — are inlined into your HTML at serve time, so
they are part of the cached document rather than something it has to fetch. On an
offline cold boot `fetch`/`XMLHttpRequest` are patched as usual, and a proxied
call fails as an ordinary network error you can catch, not as a CSP violation.

**You get an identity for free.** Unless the app is `public`, the edge only serves
signed-in users; `GET /_api/me` returns the current actor as
`{user: {id, displayName, email}}`. Don't build a login screen.

Use `id` — the user's directory object id (`oid` claim) — as the key for anything
you store about a person; it is stable for the life of the user and it is what
the app-data scopes already partition on. `displayName`
and `email` are for **display**: `email` is `null` when there is no address to show
(a shared-password app signs everyone in as `Guest`), so handle that rather than
rendering "null", and never treat it as an identity or a delivery target.

---

## 2. The capability manifest

The manifest declares what the app is allowed to do, and the gateway enforces it.
It exists **before any code is deployed** and is edited in the portal (Capabilities
tab) or over `GET`/`PUT {{PORTAL_ORIGIN}}/api/v1/apps/<slug>/manifest`. A capability
you did not declare returns `403` — that is the expected failure, not a bug.

```jsonc
{
  "app": "my-app", // the slug
  // internal | password | public, or { "mode": "group", "groupIds": ["<id>", ...] }
  // for "any of these directory groups" (max 10). `group` only works once the
  // deployment emits group claims — set it from the portal's Access tab, which
  // has a picker, rather than guessing ids here.
  "visibility": { "mode": "internal" },
  "capabilities": {
    "llm": {
      "models": ["claude-haiku-4-5"], // exact ids; anything else is 403 model_not_allowed
      "dollarsPerDay": 5 // daily spend cap in USD; omit for the install default
    },
    "data": {
      "user": true, // per-user private store
      "collections": ["signups"], // append-only, write-only from the app
      "sharedRead": ["config"], // app-scoped world-readable keys
      "sharedWrite": [], // a write grant never implies a read grant
      "sharedReadPrefixes": ["record:"], // ADR-0042: every key starting with these
      "sharedWritePrefixes": ["record:"], // same, write — REQUIRES writesPerDay (below)
      "writesPerDay": 10000, // the bound the write prefixes are approved against
      "bytesPerDay": 50000000
    },
    "mcp": [], // carried, not yet enforced — no transport exists
    "externalOrigins": [], // direct browser calls: widens CSP connect-src/img-src
    "fetch": {
      "origins": [
        { "origin": "https://api.github.com" }, // keyless proxied call
        { "origin": "https://api.stripe.com", "connection": "stripe-test" }, // stored secret, injected server-side
        { "origin": "https://app.acme.example", "provider": "acme", "required": true } // OAuth provider — see §3.5
      ],
      "requestsPerDay": 10000
    },
    "shim": { "fetch": false, "connect": false } // injected helpers — see §3.4 (fetch) and §3.5 (connect)
  }
}
```

Models this platform prices and will serve: `{{LLM_MODELS}}`. Ask for the cheapest
one that does the job — `claude-haiku-4-5` is the sensible default for classification,
extraction, and short generation.

**Some grants need a human.** Staying inside the baseline (curated models,
≤ ${{BASELINE_DOLLARS_PER_DAY}}/day of LLM, ≤ {{BASELINE_WRITES_PER_DAY}} writes/day,
≤ {{BASELINE_BYTES_PER_DAY}} bytes/day, ≤ {{BASELINE_FETCH_REQUESTS_PER_DAY}} proxied
requests/day) applies immediately. Adding an `externalOrigins` entry, any `fetch.origins`
entry, any `mcp` server, any `sharedReadPrefixes`/`sharedWritePrefixes` entry (one
prefix covers unboundedly many keys), going `public`, or exceeding a baseline queues
an **approval** for a platform admin. Plan for the wait; don't design around it by,
say, hardcoding a key in the bundle.

`connection` names a secret the platform stores and injects server-side. You never
see its value, and you never put credentials in app code or in the manifest.

`provider` names an OAuth **connection provider** the operator registered (the
Capabilities tab lists the refs you can bind, per environment). At call time the
platform injects the signed-in user's own connection to that provider — their
OAuth access token, custodied server-side — so each user brings their own grant
and no token ever reaches your code. One credential source per origin: an origin
binds `connection` or `provider`, never both. `required` on a provider binding
is a dependency hint for reviewers — it never blocks anything; an unmet binding
just fails the call (§3.5).

---

## 3. The gateway — `/_api/*`

Same-origin, cookie-authenticated, no CORS, no key. Call it with a plain `fetch`
from your app. Mutating calls are Origin-checked, so they must come from the app's
own page — not from a `curl` in a terminal.

### 3.1 LLM — `POST /_api/llm/chat`

Provider-neutral on purpose; do not reach for an OpenAI or Anthropic SDK.

```js
const res = await fetch("/_api/llm/chat", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    model: "claude-haiku-4-5", // must be in capabilities.llm.models
    system: "You are terse.", // top-level, NOT a message with role "system"
    messages: [{ role: "user", content: "hello" }], // roles: user | assistant only
    maxTokens: 1024, // default 1024, max 128000
    stream: true, // default true
  }),
});
```

With `stream: true` (the default) the response is Server-Sent Events:

```
event: delta   data: {"text":"..."}                       zero or more
event: done    data: {"stopReason":"...","usage":{...}}   terminal, success
event: error   data: {"code":"...","message":"..."}       terminal, failure
```

Read it with a `fetch` body reader — `EventSource` cannot POST. With
`stream: false` you get one JSON body: `{ model, content, stopReason, usage }`.

Every call is priced and metered against the app's daily budget, and the owner can
see it in the portal.

**Structured output.** Add `responseFormat` to get JSON that matches a schema
instead of prompt-begging for it and parsing defensively:

```js
body: JSON.stringify({
  model: "claude-haiku-4-5",
  messages: [{ role: "user", content: "Rome, 3 days" }],
  maxTokens: 4096, // give the JSON room — see the truncation note below
  stream: false,
  responseFormat: {
    type: "json_schema", // the only mode
    name: "itinerary", // optional, [A-Za-z0-9_-]{1,64}
    schema: {
      type: "object", // the root must be an object
      properties: { days: { type: "array", items: { type: "string" } } },
      required: ["days"],
      additionalProperties: false, // required — the schema is always enforced
    },
  },
});
```

The JSON comes back as ordinary `content` (or ordinary `delta` frames when
streaming) — `JSON.parse` it yourself. The schema is always **enforced** (there is
no best-effort mode), so write to the strict subset: every key in `required`,
`additionalProperties: false`, no recursion, and no `minLength`/`minimum`-style
constraints. Keep schemas under 32 KB and 12 levels deep.

**Set `maxTokens` generously, and check `stopReason` before parsing.** Prose degrades
gracefully when it hits the cap; JSON does not — you get a truncated, unparseable
fragment and a `JSON.parse` throw. Omitting `maxTokens` on a `claude-*` model means
`1024`, which a nested schema will blow through. Check
`stopReason !== "max_tokens"` (non-streaming) or the `done` frame's `stopReason`
(streaming) first.

If the platform returns `400 validation_failed` mentioning `responseFormat.schema`,
the vendor rejected your schema for being outside the strict subset above — fix the
schema; retrying unchanged will not help.

Not every model can enforce a schema. `claude-haiku-4-5`, `claude-opus-4-8`,
`claude-opus-5`, `claude-sonnet-5`, `claude-fable-5` and `claude-fable-5-1` can;
`claude-opus-4-7`, `claude-opus-4-6` and `claude-sonnet-4-6` cannot, and asking gets
a `400` — they still work fine for plain text chat.

### 3.2 App data — `/_api/data/*`

Three named access patterns, not a symmetric key-value store. Values are opaque
JSON up to **64 KiB**; keys, prefixes, and collection names are printable-ASCII
identifiers — `0x20`–`0x7E`, 1–256 characters, no leading/trailing space. Identifiers, not
prose: put human language in the VALUE, which can be any JSON.

```
PUT    /_api/data/user/:key          store a value for the signed-in user
GET    /_api/data/user/:key          read it back
DELETE /_api/data/user/:key
GET    /_api/data/user               list this user's keys
POST   /_api/data/collections/:name  append one item  → 201, empty body
GET    /_api/data/shared/:key        app-scoped, readable by every user
PUT    /_api/data/shared/:key        concurrency precondition REQUIRED — below
GET    /_api/data/shared?prefix=p    list keys under a granted prefix (ADR-0042)
```

- **`user`** is partitioned by the signed-in user by the database itself. A `public`
  app has no user scope and gets `403`.
- **`collections`** are **append-only and unreadable from the app** — there is no
  list, get, or delete verb, and adding one is not possible from app code. This is
  the right shape for a signup form, a feedback box, a survey. The owner drains the
  collection from the portal. Anonymous visitors of a `public` app may append.
- **`shared`** keys are visible to everyone who can open the app. Never put anything
  user-specific or sensitive there.

**Shared writes are compare-and-swap, and the precondition is mandatory.** Every
read of a `user` or `shared` key returns an `ETag: "<version>"` header — an opaque
token, not a timestamp; never parse it. A `PUT /_api/data/shared/:key` must carry
either `If-Match: "<version>"` (the ETag from your last read — write only if the
value hasn't moved) or `If-None-Match: *` (create the key only if it doesn't
exist). A shared PUT with neither is refused `428 precondition_required`, and a
stale version gets `412 conflict` — someone else wrote between your read and your
write, so re-read, re-apply your change, and retry. Neither failure is charged
against `writesPerDay`, but retries must be **bounded**. `If-Match: *` is refused
everywhere: it asserts nothing. `user`-scope writes may omit the precondition
(last-write-wins is fine when the only race is one person's two tabs), but honor
it when sent.

```js
// The canonical shared-write loop: read → modify → If-Match → retry on 412.
async function updateShared(key, mutate) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await fetch(`/_api/data/shared/${key}`);
    // A failed read is NOT "key absent" — without this guard a 403/429/503
    // falls into the create branch, 412s three times, and misreports the real
    // failure as contention.
    if (!res.ok && res.status !== 404) throw new Error(`read failed: ${res.status}`);
    const current = res.status === 404 ? undefined : (await res.json()).value;
    const etag = res.headers.get("etag"); // null when the key doesn't exist yet
    const put = await fetch(`/_api/data/shared/${key}`, {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        // Claim an unwritten key; otherwise CAS on exactly what you read.
        ...(etag ? { "if-match": etag } : { "if-none-match": "*" }),
      },
      body: JSON.stringify(mutate(current)),
    });
    if (put.ok) return;
    if (put.status !== 412) throw new Error(`shared write failed: ${put.status}`);
    // 412 = lost a race; the loop's re-read picks up the winner's value.
  }
  throw new Error(`"${key}" is contended — gave up after 3 attempts`);
}
```

A key in `sharedWrite` but not `sharedRead` can't be re-read (GET is `403`), so
the loop's re-read can't work there. The 412 body still tells you what to CAS
against: retry once with `if-match: "<error.details.currentVersion>"`. That is a
**blind overwrite** — you never saw the value you're replacing — so prefer
granting `sharedRead` on any key an app writes.

**Prefix grants are how a shared namespace grows at runtime.** The literal
`sharedRead`/`sharedWrite` arrays are fixed at deploy time — an app whose
records are created by users (`record:<id>`, one per submission) cannot
enumerate the ids in a manifest. `sharedReadPrefixes`/`sharedWritePrefixes`
authorize every key that *starts with* the prefix (exact `startsWith`; no
wildcards), and they unlock the list verb, which returns keys + versions —
never values — paginated at 200 keys per page:

```js
// Create a record at a natural key: create-if-absent is the dedup. Two users
// can never generate the same id, and if they somehow did, exactly one wins.
const id = crypto.randomUUID();
await fetch(`/_api/data/shared/record:${id}`, {
  method: "PUT",
  headers: { "content-type": "application/json", "if-none-match": "*" },
  body: JSON.stringify(record),
});

// The index view: ONE list call. Do NOT keep a "record-index" key of your own —
// it's a 64 KiB-capped value with a lost-update race on every creation.
const page = await (await fetch("/_api/data/shared?prefix=record:")).json();
// page = { keys: [{ key, version, updatedAt }, ...], nextCursor? }
// Pass nextCursor back as ?cursor=… until it's absent. The listed version is a
// valid If-Match, so list → update needs no per-key read.
for (const k of page.keys) {
  const { value } = await (await fetch(`/_api/data/shared/${encodeURIComponent(k.key)}`)).json();
}
```

The prefix must itself be covered by a `sharedReadPrefixes` grant (equal or
narrower), a literal `sharedRead` grant does not confer listing, and there is
no prefix-less form. `403` on a list means the prefix wasn't granted — that is
the enumeration boundary, and it's audited.

**A write prefix requires a `writesPerDay` budget.** Before prefixes, the
literal `sharedWrite` array bounded the rows an app could ever hold; a prefix
allows creating a NEW row per call, and nothing can delete shared rows yet — so
the manifest refuses `sharedWritePrefixes` without `writesPerDay` (a 400 naming
the field). Read prefixes need no budget: they can't create rows, and listing
is page-capped.

```js
await fetch("/_api/data/user/prefs", {
  method: "PUT",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ theme: "dark" }),
});
const prefs = await (await fetch("/_api/data/user/prefs")).json();
```

### 3.3 Outbound HTTP — `/_api/fetch/<url>`

Prefix the absolute target URL onto the path. The method, headers, and body pass
through; the platform resolves and injects any `connection` credential — or, on
a provider-bound origin, the signed-in user's own OAuth connection token
(§3.5) — blocks private/loopback/metadata addresses, refuses redirects, and
streams the response back.

```js
const r = await fetch("/_api/fetch/https://api.github.com/repos/vercel/next.js");
```

The target's origin must be listed in `capabilities.fetch.origins`. Your own
`cookie` and `authorization` headers are never forwarded upstream. WebSocket,
`EventSource`, and `<img>`/`<form>`/font loads do **not** go through the proxy —
those need `externalOrigins` instead.

### 3.4 The transparent shim

Setting `capabilities.shim.fetch: true` makes the edge inject a small script into
your HTML that patches `fetch` and `XMLHttpRequest` so calls to granted origins are
rewritten onto `/_api/fetch/<url>` automatically. Useful when porting code that
already calls a third-party API directly. Prefer writing the `/_api/fetch/` path
yourself in new code — it is explicit and it works without the shim. (The legacy
spelling `capabilities.fetch.shim: true` still parses; declare the `shim` block.)

### 3.5 Connected accounts — OAuth providers and the connect flow

An origin bound to a `provider` uses **the signed-in user's own OAuth connection**
to that provider. Connections are per user and are created only by **explicit
consent**: the platform never opens a popup on its own, never watches your
responses, and never retries anything. Your app offers the user a Connect
control — a visible, labelled `<button>` ("Connect to …") — and calls one of the
two entries below **from inside its click handler**. Both require a user gesture;
without one the browser refuses the popup.

**Entry 1 — the helper (opt-in).** Grant `"shim": { "connect": true }` and the
platform inlines `window.helix.connect()` into your HTML. It never throws and
never rejects — every result is an outcome:

```js
connectButton.addEventListener("click", async () => {
  const result = await window.helix.connect("acme"); // the provider ref
  // result = { outcome, provider, attempt?, reason? }
  if (result.outcome === "connected" || result.outcome === "already_connected") {
    await refetchVendorData(); // re-issue the call that failed with connection_required
  }
});
```

Outcomes: `connected` (the user approved; connection saved),
`already_connected` (a working connection existed — nothing was sent to the
vendor), `denied` (the user declined at the vendor), `cancelled` (popup closed
without completing — the helper tells the platform so a late completion cannot
claim the attempt; if it completed just before closing, your next call
succeeds), `timeout` (five minutes with the popup open), `blocked` (the browser
refused the popup — offer Connect again; the platform never navigates your tab
or retries the open), `signin_required` (no app session — sign in, then Connect
again), and `error` (platform-side; `reason` ∈ `conflict`,
`provider_unavailable`, `provider_misconfigured`, `provider_incompatible`,
`service_unavailable`).

**Entry 2 — no helper.** Open the start route in a popup from the same click
handler and listen for the completion message yourself:

```
GET /_api/connections/:ref/start          optionally ?attempt=<correlation tag>
```

Same-origin navigation on your app's host (it runs the session gates). On
success the popup goes straight to the vendor's consent screen; otherwise a
platform page posts the outcome message and offers Close. **Verify every
message before trusting it** — it is a notification, never an authorization
grant (it carries no token):

1. `event.source` is the popup you opened;
2. `event.origin` is a platform origin — your app's own host, or the auth host
   (completion pages);
3. the body parses: `source: "helix-connect"`, `version: 1`, `provider` matches
   the ref you are connecting, `outcome` in the helper's set, `reason: null`
   unless the outcome is `error`, and `attempt` matches the tag you sent — when
   the message carries one.

Discard anything else.

**When the call fails.** A provider-bound API call answers `{code, message,
provider?}` when it cannot be served. The one the user can fix is `403
connection_required` (no connection yet, declined consent, dead token,
disconnected, reconnection required): offer Connect again, and on a
`connected`/`already_connected` outcome re-issue the call. **Helix never
replays a call — retrying, or not, is your decision.** `provider_unavailable`
(503) and `provider_misconfigured` (502) are administrator problems; retrying
does nothing. For anonymous visitors on a `public` app and shared-password
pseudonyms, `connection_required` is permanent — those identities cannot hold
connections, so do not show them a Connect control.

**`required: true` is a hint, not a check** — it documents the dependency for
reviewers and never blocks, gates, or pops anything.

### 3.6 Errors worth handling

| Status | Code                     | Meaning                                                              |
| ------ | ------------------------ | -------------------------------------------------------------------- |
| 401    | —                        | Not signed in (a fetch after the session expired; reload to re-auth) |
| 400    | `validation_failed`      | Bad request body — or a `responseFormat` this model can't enforce    |
| 403    | `forbidden`              | Not in the manifest — or a key/prefix no grant covers (incl. list)   |
| 403    | `model_not_allowed`      | Model isn't in `capabilities.llm.models`                             |
| 403    | `connection_required`    | No user connection to a provider-bound origin — offer Connect (§3.5) |
| 412    | `conflict`               | Lost a shared-write race — re-read and retry with the new `ETag`     |
| 428    | `precondition_required`  | Shared write without `If-Match`/`If-None-Match` — fix the code       |
| 429    | `quota_exceeded`         | Daily budget spent — in-flight calls finish, new ones are refused    |
| 429    | `rate_limited`           | Anonymous per-IP limit on a `public` app                             |
| 429    | `rate_limited`           | The upstream model is throttled — retry after the `retry-after` delay |
| 502    | `upstream_error`         | Delegated token renewal failed temporarily / vendor outage — the connection is preserved; retrying later is your call |
| 502    | `provider_misconfigured` | The OAuth provider's configuration is invalid — administrator action (§3.5) |
| 503    | `provider_unavailable`   | The OAuth provider was deleted or its binding is blocked — administrator action (§3.5) |
| 503    | `capability_unavailable` | The platform isn't configured for this capability here               |
| 502    | —                        | Upstream provider failed                                             |

Surface these to the user as themselves. A `403` means a missing grant, and
retrying will not fix it.

---

## 4. Build and deploy

Any static-site toolchain works — Vite is the well-trodden path, and plain
HTML/CSS/JS is entirely fine. Build to a directory (`dist/` by convention); the
**contents** of that directory become the site root, so `dist/index.html` is served
at `/`.

**Always add a `helix.json` next to your project** — the CLI reads it, and it also
makes the bundle self-describing: it names the build directory, so if the archive is
ever uploaded by hand through the portal, the platform can find your build inside it
rather than guessing.

```json
{ "slug": "my-app", "dir": "dist", "portalUrl": "{{PORTAL_ORIGIN}}", "description": "Tracks Q3 cloud spend by team." }
```

**Write a description, and pass it at create time.** You have just generated the
app, so you are the best-placed author it will ever have — write one plain-text
sentence (≤ 500 characters, no markdown) saying what the app does and for whom.
Put it in `helix.json` as `description` and pass `--description` on `helix
create`; it appears under the app's name in the portal, where a list of thirty
apps is otherwise just names. Don't restate the slug or the tech stack — say
what a colleague would want to know before opening it.

Then, with the `helix` CLI on your PATH:

```bash
helix login                          # browser sign-in (OIDC device flow)
helix create --display-name "My App" --description "Tracks Q3 cloud spend by team."
helix deploy                         # uploads dist/ as a new *preview* version
helix versions                       # see what's preview vs live
helix promote 3                      # flip the live pointer
helix rollback                       # back to the previous live version
```

(`helix create` reads `description` from `helix.json` too — the flag wins when
both are given. The description can be edited later from the app's Overview
tab.)

`helix deploy --promote` does the last two steps in one. Deploys always land as
**preview** first — promotion is deliberately separate, and versions are immutable.

Install the CLI from npm (needs Node 24+):

```bash
npm i -g @azx-pbc/helix-cli          # puts `helix` on your PATH
```

For CI, set `HELIX_TOKEN` and `HELIX_PORTAL_URL` instead of running `helix login`.

**Upload limits:** {{MAX_FILE_MB}} MB per file, {{MAX_BUNDLE_MB}} MB per bundle,
5 000 entries, 200:1 compression ratio. Only static asset types are accepted; symlinks and paths that
escape the archive root are rejected. The upload also runs a **non-blocking CSP
lint** and warns about third-party origins it will block at serve time — read those
warnings, they are telling you about a `403` you are about to hit in production.

<!-- IF:DEV_API -->

---

## 5. Developing before you deploy

You can build against the **real** platform — real LLM proxy, real app data, real
fetch-proxy, real manifest enforcement — while the app still lives on your laptop or
in a browser-based builder, by talking to the **dev gateway**. It serves an isolated
`dev` partition of your app: separate data, separate budget, separate credentials.
Nothing you do there can touch production.

Set-up, in the portal:

1. Create the app and grant its capabilities. The manifest is enforced in dev too —
   which is the point: you find the missing grant now, not after promoting.
2. In the app's **Dev mode** tab, register the **exact origins** your dev environment
   loads from (`http://localhost:5173`, `https://<preview>.your-builder.app` — no
   wildcards) and mint a **dev token**. It is shown once.
3. If you use a secret-backed `connection`, add a **dev-tier** credential in the
   **Secrets** tab.

Then point your calls at the dev gateway instead of `/_api/*`. The slug moves into
the path, and the token replaces the session cookie — **everything else about the
request is identical**, so keep the base URL in one constant and swap it at build
time:

```js
const API = import.meta.env.DEV ? "{{DEV_API_BASE}}/<slug>" : "";

await fetch(`${API}/_api/llm/chat`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    ...(API && { authorization: `Bearer ${import.meta.env.VITE_HELIX_DEV_TOKEN}` }),
  },
  body: JSON.stringify({ model: "claude-haiku-4-5", messages: [{ role: "user", content: "hi" }] }),
});
```

Deploying moves **code**, never data — there is no "copy my dev rows to prod", and
the portal offers a reset for the throwaway dev partition.

**Connecting a provider in dev (§3.5) changes shape, not behavior.** The helper
is not injected on your dev origin — the platform serves only your `/_api/*`
calls there — so use the raw entry: `POST {{DEV_API_BASE}}/<slug>/_api/connections/:ref/start`
with the dev bearer token answers `{outcome: "started", popupUrl}` — open the
returned single-use URL in a popup — or a terminal `already_connected` /
`not_available`. The completion message arrives from the auth host; verify it
exactly as §3.5 says. The connection is the dev partition's, like every other
dev credential.

<!-- /IF:DEV_API -->

---

## Checklist before you call it done

- [ ] No server code, no `.env`, no API key anywhere in the bundle.
- [ ] Every third-party call goes through `/_api/fetch/<url>` (or has an approved
      `externalOrigins` grant) — nothing relies on plain cross-origin `fetch`.
- [ ] Every capability the code uses is declared in the manifest, with a budget.
- [ ] `403` and `429` from the gateway are handled and shown to the user.
- [ ] A provider-bound origin has a visible, labelled Connect `<button>` calling
      the connect entry from its click handler (§3.5); `connection_required`
      offers Connect and the app re-issues the call — nothing retries
      automatically.
- [ ] User-specific state is in `/_api/data/user/*`, not in `shared`.
- [ ] Every `shared` write goes through the read → `If-Match` → retry-on-`412`
      loop (or `If-None-Match: *` to create) — a plain shared PUT is refused.
- [ ] No self-maintained "index" key over a growing shared namespace — the list
      verb (`?prefix=…`) is the index (ADR-0042).
- [ ] Nothing sensitive is written to a `shared` key or logged to the console.
- [ ] The build output has an `index.html` at its root and deploys clean of CSP
      lint warnings.
