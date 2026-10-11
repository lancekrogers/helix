# Connection providers (OAuth)

> **Related ADRs:** [ADR-0031](../adr/0031-connection-providers-delegated-auth.md) (connection providers and delegated auth) · [ADR-0006](../adr/0006-secret-custody-seam.md) (secret custody) · [ADR-0002](../adr/0002-postgres-role-split-rls.md) (role split + RLS).

The operator-facing half of the OAuth-connections feature: the **provider
catalog** — administrator-configured vendor OAuth registrations — and **My
Connections**, where any signed-in user sees and ends their own consent. The
app-author half (manifest bindings, the connect helper, the error codes) is in
[fetch-proxy.md](./fetch-proxy.md). Custody internals shared with connection
secrets are in [secrets-and-connections.md](./secrets-and-connections.md).

A **provider** is one vendor integration in one environment. A **connection**
is one user's consent to it. Providers are control-plane data: created, edited,
imported, and exported in the portal without redeploying, and distributed to
`helix-egress` over LISTEN/NOTIFY so a cached configuration never outlives the
row (ADR-0031 decision 6). The provider `kind` ships
`rest-delegated` only — other kinds join the enum when they are implemented, so
a kind that cannot serve a call cannot be configured.

## Routes

All under `/api/v1`, bearer-gated through the portal's verifier chain; every
provider route is admin-only and audited.

| Route | Purpose | Notable responses |
| --- | --- | --- |
| `GET /api/v1/providers` | list (metadata only) + the deployment's callback URL | — |
| `POST /api/v1/providers` | create | 409 duplicate ref+env; 422 validation |
| `GET /api/v1/providers/:id` | edit-form source + inspect | 404 unknown |
| `PUT /api/v1/providers/:id` | edit (carries the loaded revision) | 409 stale revision; 409 `confirmation_required` with impact; 422 |
| `DELETE /api/v1/providers/:id` | delete (carries the same acknowledgement) | 200 `already_removed` on repeat; 409 `confirmation_required` |
| `GET /api/v1/providers/:id/impact` | bound apps, connection count, pending attempts | — |
| `GET /api/v1/providers/:id/export` | credential-free JSON download | failure = error, never a partial file |
| `POST /api/v1/providers/import/preview` | parse + validate + collision/diff preview | 400 malformed |
| `POST /api/v1/providers/import` | apply in the chosen mode | same rules as create/edit |

The SPA surfaces are `/admin/providers` (list, env badges + All/Dev/Prod
filter), `/admin/providers/new`, and `/admin/providers/:id` (edit form with the
sensitive-change review panel).

## Provider configuration

A provider row carries: a **ref** (lowercase letters, digits, hyphens — the
secret-name convention, ≤64 chars; the key manifests and the catalogue use),
a display name, the **environment**, the vendor's authorize and token
endpoints, the OAuth client ID and client secret, the requested permissions,
the API destinations, and the **token placement** — how the user's delegated
access token is presented to the vendor's API: `Authorization: Bearer` (the
default) or one explicitly named header. Query-string tokens and signing
recipes are not representable for a delegated user token.

`ref`, `kind`, and `env` are identity — fixed at create. Everything else is
editable.

**Client credentials are write-only.** They cross the API boundary in plaintext
only on create, on an edit that supplies them, and on an import apply; the
portal seals them onto the row through the `SecretStore` (kv-connections — the
portal seals, egress opens, the edge has no grant). No read, no list, and no
export ever returns them: the metadata response shape structurally omits the
credential fields, so "not returned" cannot drift into "returned empty".

**Revision and stale saves.** Every sensitive mutation advances the row's
`revision` — one field serving three consumers: admin concurrency, the egress
cache, and consent staleness. An edit submits the revision it
loaded; if the row moved on, the save is rejected with a 409 and the form keeps
the draft — reload, review the current settings, confirm again. Two concurrent
credential rotations arbitrate the same way: the loser's sealed material is
released, not stranded.

**The fixed callback URL.** The providers list shows the deployment's single
OAuth callback — `https://auth.<control base>/connections/callback`, from
`CONTROL_PUBLIC_BASE` (defaulting to the apps base in single-domain layout) —
with a copy button and the instruction to register that exact value with the
vendor. One configured value serves every provider (ADR-0031 decision 10).

After a domain-split cutover, confirm `callbackUrl` in `GET /api/v1/providers`
matches `https://auth.<EDGE_CONTROL_DOMAIN>/connections/callback` on the edge.
That check is the only way to spot an edge/portal mismatch before vendor OAuth
fails (**unverified in Azure** until you run it on your install).

## JSON import / export

The text backstop is the JSON document, round-tripped through one shared
schema — there is no second format and no in-portal free-text editor.

**Export** re-reads the current configuration and produces
`{version: 1, provider: {…}}`: ref, display name, kind, endpoints, requested
permissions, API destinations, token placement. It carries **no client
credentials, no tokens, no secret references, and no environment** — it can be
committed, shared, and re-imported elsewhere safely. A failed read surfaces as
an export failure; a partial file is never offered. Repeating an export
changes nothing.

**Import** never applies blind. The file is parsed and validated against the
same schema the form uses, and the preview panel shows either the blocking
validation errors or the parsed fields plus an explicit mode:

- **Create a new provider** — choose the environment; client ID and secret are
  entered at apply (credentials are never imported). An existing ref+env
  collision is surfaced in the preview; it never becomes an implicit update.
- **Update an existing provider** — name the target explicitly; a name
  collision never silently selects one. The preview shows the per-field diff
  against the target's current values, flags the sensitive fields among them
  (by the same comparison the apply path's confirmation gate runs), and offers
  an optional client-secret replace (blank preserves the existing credential).

Apply reports created/updated or a distinguishable failure; a rejected import
leaves the provider unchanged; a lost apply response is outcome-not-confirmed —
refresh and review before importing again.

## Edits and deletion: impact, confirmation, invalidation

A **sensitive field set** is fixed once in `@azx-pbc/shared` and consumed
identically by the edit route, the import path, and the invalidation
transaction: client identity, authorize/token endpoints, requested permissions,
API destinations, and token placement. Changing the display name or rotating
the client secret is **not** sensitive — both preserve connections and
approvals. (Client-secret rotation is "supply a new value"; the sealed material
is never read back, so blank means keep.)

A sensitive delta submitted without an explicit invalidation acknowledgement is
rejected **409 `confirmation_required`**, carrying the impact payload — the
apps bound to the provider, the number of live user connections, and the number
of pending consent attempts. Nothing is applied and nothing is sealed before
the confirmation. The SPA renders the same counts in a review panel above a
field diff, with the warning sentence: existing connections and pending consent
attempts become invalid, and affected apps need approval again; Helix does not
create reapproval requests for them.

On confirm, one all-or-nothing transaction applies the settings write with the
revision bump, invalidates the affected user connections, kills the pending
consent attempts, and records the audit row. An interrupted edit leaves
everything exactly as it was.

What invalidation means downstream:

- The invalidated connections stop resolving — the next delegated call answers
  `connection_required`, and the provider-bound origin reads as blocked (503
  `provider_unavailable` when the provider row itself is the thing that moved).
  The full error table is in [fetch-proxy.md](./fetch-proxy.md).
- Affected apps' manifest bindings stop being effective. The Capabilities tab
  shows a **Reapproval needed** badge per bound origin.
- Pending consent popups die at their next step.

**Deletion** is always invalidating, so its confirmation is never optional.
A repeated delete of an already-removed provider answers `already_removed`,
keyed by the provider's surrogate id — it can never touch a replacement
provider recreated under the same ref. Recreating a provider with the same ref
restores nothing: old approvals and old consent stay gone. The removed row's
sealed credentials are released after the row is gone; a failed release is
reported (`provider.destroy_failed` audit event + error log) and never
un-deletes the row.

## Reapproval is owner-requested

After a sensitive edit or a deletion, nothing re-approves automatically. The
app owner resubmits by saving the manifest again: a save that still declares a
binding whose stamps have all gone stale **re-elevates it** — the write-gate
files it as a fresh, re-stamped (against the provider's current revision)
high-risk add even though the value is unchanged, because the classifier's
value-diff can no longer see it. An administrator approves the re-add like a
first grant, and the binding is effective again. An approval filed against a
provider configuration that changed after filing is rejected with a conflict
and must be resubmitted. There is no auto-reapproval queue — a privilege grant
is re-granted by a person, on request.

## Environments

Providers are env-partitioned end to end. `env` is chosen explicitly at create
and immutable after; the same ref may exist once per environment. Dev-tier
connections resolve only dev-tier providers and key to the dev caller's
developer identity; prod resolves only prod connections for signed-in
principals. A provider never moves between environments — configure each tier
deliberately. The catalogue exposes raw env-pinned rows
(`GET /api/v1/capabilities` → `fetch.providers`), so an app author sees exactly
what each tier can bind.

## Registering a vendor (Asana) — prerequisites and process

Helix does not own the OAuth client. Each deployment registers its own client
with the vendor out-of-band — a Helix-held client secret would let every
customer deployment impersonate the platform against every other customer's
tenant (ADR-0031 decision 11). The process, prerequisites only:

1. **Register the OAuth client with the vendor** (here: Asana's developer
   console — self-serve; registration programmes change, so re-verify against
   the vendor's current docs).
2. **Register the fixed callback URL** — the exact value shown on the
   providers list page. Several vendors require exact-match redirect URIs;
   one stable value means every provider pastes the same string.
3. **Enter the client ID and secret** on the provider form. They are sealed on
   write and never re-displayed or exported.
4. **Check organization-level app allowlisting.** Some vendors' enterprise
   plans let an organization allowlist integrations. Where that is on and the
   platform's app is not pre-approved, *every* user hits a consent wall —
   allowlisting is a deliberate onboarding step, not a per-user follow-up.
5. **Configure the requested permissions and API destinations** on the form;
   consent grants exactly the configured permissions, and the connect-time
   gate refuses an incomplete grant.

The vendor-specific observed behavior from the live deployment exercise (the
deployment-acceptance record) lives in
[`docs/runbooks/asana-deployment-acceptance.md`](../runbooks/asana-deployment-acceptance.md) —
pending until performed; this doc carries the process, not the observations.

## What disconnection does — and does not do

Disconnecting (in My Connections) ends **Helix access**: the row is invalidated
in one transaction — the retirement ledger mark commits with the status flip —
so resolution and renewal refuse immediately, including through another running
instance, and pending consent attempts for that connection die.

It does **not** reach the vendor. Dispatched vendor operations already in
flight may finish, and the vendor-side authorization itself remains — remove
the grant at the vendor if you want it gone. The confirmation dialog states
both, and names the apps sharing the connection in that environment.

Retired material is destroyed by the egress sweep within the recovery bound
(15 minutes). A failed destroy is visible on the
retirement metric and in a warn log, and is retried without manual
intervention. Cleanup never touches a current connection's material.

## My Connections

`/connections` — a Workspace nav item, available to every signed-in principal,
is the one user-scoped portal surface. One card per connection: provider
display name and environment badge, connected date, granted permissions as
badges, a status line — **Connected** or **Reconnect needed** — and
**Disconnect**.

The status is Helix's own row state. It never claims to have verified the
vendor-side grant, and the page shows no vendor profile. Apps ask the same
question about their own users through the app-facing status read
(`GET /_api/connections/:ref/status` — [fetch-proxy.md](./fetch-proxy.md)),
which shares this posture and this collapse of unhealthy states.

Disconnect asks for confirmation (the sharing apps, the two limits above), then
stops Helix access as described above. Repeating a disconnect of an
already-removed connection answers "Already removed" and cannot affect a newer
connection re-established afterwards. A lost response is shown as outcome not
confirmed — refresh My Connections and confirm again; nothing auto-resubmits.
The list refreshes on page entry, after actions, on explicit Refresh, and every
30 seconds while the page is visible (paused while hidden, refreshed on
return).

## Key files

- `apps/portal/src/routes/providers.ts` — provider CRUD, export/import, the impact route, and the invalidation transaction.
- `apps/portal/src/routes/connectionsInternal.ts` — the internal consult, cancel, and connection-status routes (edge→portal, internal JWT).
- `apps/edge/src/routing/connectionStatus.ts` — the app-facing status read (prod); the dev twin is `apps/edge/src/devGateway/connectionStatus.ts`.
- `apps/portal/src/routes/connectionsMine.ts` — My Connections' list + disconnect (principal-scoped).
- `apps/portal/src/connections/completion.ts` — the callback's CAS/upsert save and the `connection.connected` audit event.
- `packages/shared/src/providers.ts` — the one provider schema set: editable fields, sensitive-field list, import/export document, impact + confirmation payloads.
- `apps/egress/src/providerCache.ts`, `apps/egress/src/providerListener.ts` — the revision-keyed egress cache and its LISTEN client.

## Planned / not yet built

- **`mcp-remote` and `rest-tenant-key` provider kinds** — ADR-0031 phases 5–6;
  the tenant-key allowlist also waits on per-app RBAC (`TODO.md`).
- **A per-user vendor profile retrieval** — non-goal; My Connections shows
  Helix's own metadata only.
- **Automatic reapproval queues, provider moves between environments, and
  whole-catalog import** — all explicit non-goals.
- **An in-portal free-text editor** — deferred until the schema is big enough
  to want one; import/export is the text backstop.
