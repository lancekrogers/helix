---
title: App manifest
description: "The per-app declaration of what an app may do: app-data scopes, connections, budgets, and visibility — edited in the portal, enforced by the gateway on every call."
---

# The app manifest

Every app carries a manifest declaring what it is allowed to do. The portal
stores it, and the gateway enforces it on every call: nothing an app does at
runtime can exceed its manifest. You edit it in the portal's Capabilities tab,
or set it when you create the app.

## What an app can ask for

```ts
{
  llm: {
    models: string[]          // which models the app may call
    dollarsPerDay?: number    // daily spend cap in USD; omit for the install default
  },
  data: {
    user: boolean             // per-user key/value store
    collections: string[]     // append-only collections (no app-facing read)
    sharedRead: string[]      // shared keys this app can read
    sharedWrite: string[]     // shared keys this app can write (write ≠ read)
    sharedReadPrefixes: string[]   // same as above, by key prefix
    sharedWritePrefixes: string[]
    writesPerDay?: number
    bytesPerDay?: number
  },
  externalOrigins: string[]   // extra API hosts the browser may call directly
  fetch: {
    origins: [{ origin, connection? }]  // hosts called through the fetch proxy
    shim: boolean                       // serve-time fetch/XHR shim
    requestsPerDay?: number
  },
  offline: { scope: string }  // platform-managed service worker
}
```

Everything is a grant, and nothing is implied. An app with no `llm` block
cannot call the model gateway; an app with no `fetch` block cannot proxy an
outbound call. `user: true` gives the app a store where every signed-in user's
data is visible only to that user.

## Visibility

An app is one of:

| Mode | Who can open it |
| --- | --- |
| `internal` | Signed-in users of the deployment (the default) |
| `group` | Members of specific Entra groups |
| `password` | Anyone with the shared passphrase (must be enabled per install) |
| `public` | Anyone, no sign-in (must be enabled per install) |

## Approvals

Most manifest changes apply immediately. Changes that widen what an app can do
in riskier ways — a new proxied origin, a higher budget, going public — are
filed as an approval request for a platform admin to approve or deny. The
editor tells you which kind you are submitting before you do.

The thresholds are platform policy. Two rules to know:

- **Reducing privilege never needs approval.** Removing a grant, lowering a
  budget, or going from public back to internal all apply immediately.
- **Adding a budget is a reduction, removing one is an increase.** For data and
  fetch, an unset budget means unlimited. For the LLM spend cap, omitting the
  field uses the install default (see above), but removing an explicit cap still
  needs approval because that default may be higher or unlimited on some
  installs.

If the change contains anything that needs approval, the whole submission
becomes one pending request, and an admin sees the full diff.

## Where this is enforced

The gateway checks the manifest on every request: the model allowlist and
budget per LLM call, the key and collection grants per data call, the origin
allowlist per proxied call, and the CSP per page load. Data keys (collection
names, shared keys, prefixes) are restricted to printable ASCII, so what the
admin sees in the approval diff is exactly what was stored.

The schema lives in [`packages/shared/src/manifest.ts`](https://github.com/AZX-PBC-OSS/helix/blob/main/packages/shared/src/manifest.ts).
