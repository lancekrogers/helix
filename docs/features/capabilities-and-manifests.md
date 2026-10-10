# Capabilities & manifests

> **Related ADRs:** [ADR-0016](../adr/0016-capability-manifest-approval-classifier.md) (manifest & approval classifier) · [ADR-0009](../adr/0009-relaxed-csp.md) (relaxed CSP) · [ADR-0014](../adr/0014-same-origin-api-gateway.md) (same-origin gateway).

Each app has a manifest of permitted gateway capabilities (architecture §6.3).
The portal writes approved settings, the registry cache carries them to the edge,
and the LLM, data, and fetch handlers check them on each call. Capability grants
are per app. Group membership controls who may open an app; it does not grant
additional API capabilities.

Schema: `packages/shared/src/manifest.ts`. Visibility: `packages/shared/src/visibility.ts`.
Approval classifier + thresholds: `packages/shared/src/approval.ts`.

## The shape

```ts
Capabilities = {
  llm?:  { models: string[]; dollarsPerDay?: number }   // daily USD spend cap
  data?: { user: boolean
           collections: string[]      // append-only; no app-facing read
           sharedRead: string[]       // world-readable-within-gate keys
           sharedWrite: string[]      // narrower; write never implies read
           sharedReadPrefixes: string[]   // ADR-0042: every key starting with these (read)
           sharedWritePrefixes: string[]  // same, write — REQUIRES writesPerDay (unbounded row
                                          // creation: the grant and its bound approve together)
           writesPerDay?: int; bytesPerDay?: int }
  mcp: string[]                        // platform-registered MCP servers (default [])
  externalOrigins: URL[]               // extra CSP connect-src for DIRECT calls (default [])
  fetch?: { origins: { origin: URL; connection?: string }[]  // proxied via /_api/fetch (egress)
            shim: boolean                                     // serve-time fetch/XHR shim
            requestsPerDay?: int }
  offline?: { scope: string }          // platform-owned service worker, confined to this prefix
}

AppManifest = { app: slug; visibility: Visibility; capabilities: Capabilities }
```

Every grant string in the `data` block — collection names, literal keys, prefixes — is a
**printable-ASCII identifier** (`0x20`–`0x7E`, 1–256 chars, no leading/trailing space), one
shared rule (`isValidDataKey`) run by the manifest schema, the edge's request-time validation,
and the SPA's editor. The character set is a security decision, not a style one: those strings
render in the admin approval diff, and a blocklist passes Unicode's format characters (bidi
controls, zero-width spaces, homoglyphs) that can make a diff lie. See
[ADR-0043](../adr/0043-app-data-identifiers-printable-ascii.md). Stored VALUES stay arbitrary
Unicode JSON.

`externalOrigins` (direct browser call, widened into CSP) and `fetch.origins` (routed through the
`/_api/fetch` proxy + `helix-egress`, where a secret can be injected server-side) are the "one knob,
two settings" — same mental model, different `mode`. See [edge-serving.md](./edge-serving.md) and
[fetch-proxy.md](./fetch-proxy.md) and [secrets-and-connections.md](./secrets-and-connections.md).

`offline` is the odd one out: every other capability names something the app may *reach*, while this
one changes how the app is *served*. Declaring it makes the edge serve a platform-authored service
worker confined to `scope` and inject its registration — the app ships no worker code, and no app
bytes are ever registrable. `scope` must be a non-root path prefix with a leading and trailing
slash, and its first segment may not begin with `_` (validated on write by
`isValidServiceWorkerScope`, and re-validated in the edge's projection because the value becomes a
response header). It buys cold boot and nothing more. See
[ADR-0035](../adr/0035-offline-capability-platform-service-worker.md) and
[edge-serving.md](./edge-serving.md).

`Visibility` is a discriminated union — `internal` | `group` (+ `groupId`) | `password` |
`public` — stored flattened in the DB (`visibilityMode` + `visibilityGroupIds`, an any-of array) and reassembled
by the mappers.

## How grants flow and are enforced

1. **Author** edits the manifest in the portal: `GET`/`PUT /api/v1/apps/:slug/manifest`
   (`apps/portal/src/routes/apps.ts`), validated through `CapabilitiesSchema`. The PUT is a full
   **replace**, but it is **not** committed wholesale — it is routed through the approval
   write-gate (next section), which splits it into a part that commits now and a part that waits.
2. **Project** — the committed `capabilities` JSONB lands in `apps`, and the edge's LISTEN/NOTIFY
   projection picks it up (`apps/edge/src/registry/projection.ts`, parsing `llm`/`data`/`fetch`
   fail-closed). The live registry entry now carries `entry.llm` / `entry.data` / `entry.fetch`.
3. **Enforce** — each gateway handler checks the relevant grant per request:
   - LLM: `entry.llm` must exist and `chat.model ∈ entry.llm.models`; `dollarsPerDay` bounds the
     daily budget (see [llm-gateway.md](./llm-gateway.md)).
    - Data: `entry.data` gates the scope, and `collections` / `sharedRead` / `sharedWrite` are
      per-name allowlists; the `*Prefixes` arrays widen those to prefix matches and gate the
      shared list verb (ADR-0042); `writesPerDay` bounds writes (see
      [app-data-gateway.md](./app-data-gateway.md)).
   - Fetch: `entry.fetch.origins` allowlists proxied origins; `requestsPerDay` bounds them (see
     [fetch-proxy.md](./fetch-proxy.md)).
   - CSP: `externalOrigins` extends `connect-src` at the edge (see [edge-serving.md](./edge-serving.md)).

The asymmetry between read and write grants is deliberate: the writer and reader of app-data can
be different principals (an anonymous visitor appends to a collection the owner later drains) — see
[app-data-gateway.md](./app-data-gateway.md).

## The approval write-gate

A manifest PUT does not silently commit whatever it asks for. Capability grants, CSP origin grants,
and going public are **the same problem in three hats** — a privileged actor blessing a change to
effective policy *before* the edge enforces it — so they share one spine (`docs/design/approvals.md`).
The key structural choice: **the edge stays completely dumb about approvals.** They are a
control-plane gate on *writes* to the effective state the edge already projects; the `apps` row
holds only effective state, "requested state" is just the set of open `ApprovalRequest` rows, and
the whole system ships without touching the edge's security-sensitive code (except the independent
CSP `report-to` / `externalOrigins` loop).

**Baseline vs. elevated.** A pure classifier in `@azx-pbc/shared` (`classifyChange`,
`classifyVisibilityChange`) diffs the requested capabilities against effective state and splits the
change into a typed list of **deltas**, each tagged baseline or elevated:

- **Baseline deltas apply immediately**, in the same PUT transaction (`applyCapabilityChange` in
  `apps/portal/src/approvals/service.ts`): curated models, budgets ≤ threshold, the data scopes
  themselves (user/collections/shared keys), and **any privilege reduction**.
- **Elevated deltas** are bundled into one pending `ApprovalRequest` and gated on an admin
  decision; they do not reach the edge until approved. Routes return
  `{ applied: [...deltas], pending: <requestId|null> }`, so a single PUT can do both.

The thresholds are platform-wide policy co-located with the classifier so portal-gating and the
SPA's pre-submit warning never drift:

| Area | Baseline (applies now) | Elevated (needs approval) | Risk |
|---|---|---|---|
| LLM models | `CURATED_LLM_MODELS` (= every model in `MODEL_PRICING`: the `claude-*` family plus the OpenAI `gpt-*` models) | any other model | med |
| LLM budget | `dollarsPerDay ≤ BASELINE_DOLLARS_PER_DAY` ($50) | above threshold | med |
| data scopes | user store, collections, shared keys (literal) | shared read/write **prefixes** (ADR-0042 — one element covers unboundedly many runtime-chosen keys; a write prefix is refused without a `writesPerDay` budget, so the grant and its bound approve together) | low |
| data budgets | writes/bytes ≤ thresholds | above threshold | med |
| mcp | `CURATED_MCP_ALLOWLIST` (**empty** ⇒ *every* MCP grant elevates) | any MCP server | high |
| externalOrigins | — | any origin added | med |
| fetch.origins | — | any proxied origin (secret-bound = high) | med / high |
| offline | giving up the grant | taking it, or moving the scope | med |
| visibility | internal / group / password | **→ public** | high |

The per-delta risk travels on the delta itself (`Delta.risk`), and the admin queue renders it: one
expanded chip row per change — plain-English capability name, the change in the field's own units,
the delta's own risk badge — plus a `?` tooltip (`deltaHelp` in `@azx-pbc/shared`) explaining in
plain terms what the capability grants and why it is gated. The card's aggregate badge remains the
max across the deltas ("highest of", broken down on hover for bundles).

One rule the value-diff cannot express, added with provider bindings
([connection-providers.md](./connection-providers.md)): a binding whose
approved stamps were stale-dated by a sensitive provider edit **re-elevates on
resubmit** even though the value is unchanged — the write-gate re-files it as a
fresh stamped add, since "save the manifest to resubmit" is the only recovery
the badge offers and a pure value-diff would classify that save as empty.

**Advertised ≠ curated.** An operator can narrow what the deployment *offers* — the catalogue,
rendered skill, and SPA model picker — with `PORTAL_LLM_MODEL_ALLOWLIST` / `PORTAL_LLM_MODEL_BLOCKLIST`
(ADR-0047; on `deployFoundry` installs the Bicep derives the allowlist from `foundryModels`
automatically). That is display-surface policy only: the classifier above is unchanged, so a
hand-written manifest naming a withheld-but-catalogued model still classifies as baseline and then
fails at the upstream — the picker is where the restriction has teeth, by never offering the box.

Two invariants keep it safe without being annoying (`docs/design/approvals.md` §3):

- **Reducing privilege is always baseline** — removing a grant, shrinking a budget, public→internal
  never needs approval; only increases gate. For visibility the rule is really *crossing the tenant
  boundary*: `group → internal` widens access and is still baseline, because `internal` is the
  baseline trust level and the default. **LLM spend cap:** at the edge, an unset
  `dollarsPerDay` is enforced at the install default (`EDGE_LLM_DEFAULT_DOLLARS_PER_DAY`, $50/day
  unless changed); **data and fetch** daily caps, when unset in the manifest, stay unlimited at the
  gateway (only a defined cap is enforced on those paths). The classifier cannot read that knob, so a *requested* unset cap is treated as
  possibly unlimited and *removing* an explicit LLM cap gates; *adding* a cap (including unset →
  any number) is a reduction and commits when the new cap is at or under the $50 baseline. **Unset
  data and fetch budgets** remain unlimited (those paths only enforce a defined cap), so removing
  those caps is still a privilege increase and gates, while *adding* any budget is a reduction and
  commits.
- **Any elevated part makes the whole submission one atomic request** (the reviewer sees the full
  diff), with `risk` = the max across its deltas.

**Decide.** `apps/portal/src/routes/approvals.ts` serves the admin queue and the decision verbs
(`approve` / `deny` / `needs_changes` / `withdraw`). Approving applies the elevated deltas to the
`apps` row in one transaction → the normal `apps` UPDATE fires NOTIFY → the edge re-projects like
any other write. **Separation of duty:** the approver must differ from the requester, and admin is
membership in `PORTAL_ADMIN_GROUP_ID` carried as a **group claim in the verified bearer token**
(not an env OID list); a dev-only `PORTAL_ALLOW_SELF_APPROVE` flag (refused in prod) lets a solo
operator drive the loop. A sharp edge of the split model — baseline writes commit freely while a
request is open — is handled by a `baseSnapshot` taken at request time and an optimistic-concurrency
check at approve time that auto-bounces a stale request to `needs_changes` rather than clobbering.
(The comparison canonicalizes object-key order: the snapshot is a jsonb column, which re-orders keys
at rest, while the approve-time re-derivation emits them in schema order — the first data-area
elevated grant, an ADR-0042 prefix, surfaced that a plain `JSON.stringify` comparison read the
order difference as a moved value and bounced every data-area approve. Array order stays
significant — grants are ordered.) A pending request **never expires** — it waits for a human
decision, by design ([ADR-0039](../adr/0039-no-approval-request-expiry.md)) — so the
queue instead shows how long each request has been pending and sorts oldest-first.

**Two writers at once → `409`, never a silent overwrite** (`docs/design/approvals.md` §5). The
`baseSnapshot` check above covers a value that moved while a request *sat* pending; it does not
cover two writes landing in the same instant, so two compare-and-swaps do:

- **The decision transition** (`claimPendingRequest`) — a decision is `UPDATE … WHERE status =
  'pending'`, and on approve it is claimed *before* the `apps` write, so a decision that loses
  applies nothing. Repeating a decision that already landed is still a 200 no-op; a decision that
  disagrees with the recorded one is a 409 carrying the landed status in `error.details.status`.
  Without this a withdraw could overwrite an approval that had already granted the capability,
  leaving the queue and the audit trail saying the grant was pulled while the edge served it.
- **The effective-state write** (`casPolicyWrite`, `apps.policyVersion`) — `capabilities` is
  replaced whole, so every route that reads it and writes it back does so *inside* one transaction
  and CASes on the version it read: the manifest PUT, the visibility switch, apply-on-approve, and
  the password enable/rotate/disable routes. The loser gets a 409 telling it to reload. A change
  with no baseline part writes nothing at all and so cannot conflict — the one-click origin grant
  is entirely of that kind (every added origin is elevated), which is why two of them filed off the
  Violations screen at once both succeed.

## Where it shows up in the UI

The portal SPA has a **real** manifest editor (the Capabilities tab) wired to the live GET/PUT —
LLM models + token budget, the data flags/lists, external origins, fetch origins, and MCP grants —
and a **real Approvals queue** (`/api/v1/approvals`) with approve/deny/needs-changes/withdraw, plus
a "pending approval" banner on app detail. See [portal-web.md](./portal-web.md).

## Planned / not yet built

- **MCP** — `mcp` is carried in the manifest and the classifier already treats any MCP server as
  high-risk-elevated, but there is **no gateway transport yet**: approving an MCP grant writes the
  manifest; enforcement lands with the MCP-as-REST gateway (`docs/design/custom-backends.md`).
- **`bytesPerDay`** is declared and classified but not yet enforced at the edge (app-data design §7).
- **Per-delta partial approval** — v1 approves/denies the whole submission bundle; splitting a
  request is a deliberate future refinement (`docs/design/approvals.md` §9).
- **Approval notifications** — the queue is pull-based for v1; no push when a request is filed or
  decided.
