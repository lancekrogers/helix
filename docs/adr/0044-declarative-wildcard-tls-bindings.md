# 0044. Declarative wildcard TLS custom-domain bindings

**Status:** Accepted _(recorded 2026-09-04, implemented the same day; rollout to existing installs is per-install — see Consequences)_
**Related:** ADR [0029](0029-platform-secret-delivery.md) (the cert in the ACA environment store, not Key Vault — the fact this decision builds on); ADR [0019](0019-subdomain-per-app-isolation.md) (per-app subdomains are why a *wildcard* is needed at all); ADR [0022](0022-self-hosted-edge-not-front-door.md) (TLS terminates at the platform's own ingress, so the bindings are ours to manage); `infra/azure/README.md` "Wildcard TLS" + "Known deploy gotchas"; `apps/certbot/issue-and-bind.sh`

## Context

Wildcard TLS on the apps domain is issued by the certbot job (DNS-01, uploaded to the ACA
environment certificate store under a deterministic name — ADR-0029's reasoning for the
store, not a vault). But a **custom-domain binding is per container app**, and a cert must
**exist before a hostname can bind to it** — an ordering a declarative template cannot
express. So the bindings were made **at runtime** by the job (`az containerapp hostname
add` + `bind`, on every execution), while the template's `ingress` block carried no
`customDomains` at all.

The consequence was structural, not incidental: ARM PUTs reconcile the whole resource to
whatever the template says, so **every re-apply of the template stripped every runtime-made
binding**, and all custom domains served the ACA default cert until the job's next run
re-bound them — up to a ~24 h window in which every browser session fails TLS
verification, silent to the platform's own health checks. The documented mitigations were
procedural: re-bind after every apply (against the store, to avoid spending a Let's
Encrypt issuance), and prefer scoped `az containerapp update` over full applies.

Two facts make the ordering constraint bridgeable rather than fundamental:

- The cert's **store name is deterministic** (`wildcard-<appsDomain with dashes>`,
  derived by `issue-and-bind.sh` and used by every path in the job), so its ARM resource
  id is computable in Bicep: `<env id>/certificates/<name>`.
- Renewal **re-uploads under the same name**, and the store updates the certificate in
  place — the resource id is stable across renewals, and existing bindings track the new
  cert (the job's own runtime bind already relied on this).

## Decision

**Declare the custom-domain bindings in the template**, referencing the env-store
certificate by its deterministic resource id, gated by a one-time bootstrap param:

- `containerapp.bicep` takes an optional, **typed** `customDomains` list
  (`{ name, bindingType: 'SniEnabled' | 'Disabled' }`, certificateId) merged into the
  ingress via a `union` that **omits the property entirely when the list is empty**.
  The omission is **parity, not protection**: an absent `customDomains` and an explicit
  `customDomains: []` are the same instruction to ARM ("no bindings") and both strip
  live runtime-made bindings — the union exists so the ungated path stays byte-identical
  to the pre-declarative shape, not so an empty list is safe.
- `main.bicep` computes the cert name **once** and feeds it to both halves: the
  declarative `certificateId`, and the certbot job (injected as `CERT_NAME`, which the
  script already honours — its own derivation becomes dead-code insurance). Issuer and
  reference cannot drift.
- **`wildcardTlsBound` (default false)** bridges the one-time ordering: false on a fresh
  install (the job's runtime bind bootstraps), flipped to true after the first certbot
  run, and true forever after — at which point a re-apply preserves the bindings by
  construction. A gated apply on an install with no cert **fails loudly** at the app PUT
  (invalid certificate reference) rather than doing anything silently. The flag is set
  **literally in the params file**, never sourced from an env var: a set-but-blank env
  var renders `''` = false, and false is the silent-wipe direction.
- **The certbot job is unchanged** — including its unconditional bind steps. Post-gate
  they are (a) the fresh-install bootstrap mechanism, (b) self-heal for an apply made
  with the gate off, and (c) the thing that keeps TLS alive if a renewal ever mints a
  new certificate resource id (see Consequences). Issuance/renewal remains entirely the
  job's; the template never creates or renews certificate material.

The declared set is the edge wildcard, plus `portal.` / `dev-api.` on their own apps when
those planes are external — exactly the set the job binds today.

## Consequences

- **The re-apply wipe is gone** for gated installs, by construction rather than by
  procedure. The what-if corollary is a canary: on a gated install, what-if must never
  show `Delete properties.configuration.ingress.customDomains` — if it does, the gate is
  off; stop. Note the compiled shape changes for **all four** apps that use
  `containerapp.bicep` (ingress resolves from one expression), which is new what-if
  output, not drift.
- **The declared set is an allowlist.** A gated apply preserves exactly the declared
  bindings and **deletes anything else**, with no self-heal (the job re-binds only its
  own three). A hostname bound by hand is silently removed by the next apply — a host
  that needs a binding gets a row in `main.bicep`, not an `az containerapp hostname
  bind`.
- **Failure modes are loud or self-healing, never the old silent wipe.** Gated + cert
  absent → the apply fails at the app PUT. Ungated → today's strip-and-self-heal
  semantics, visible in what-if via the canary. Recovery for a wiped binding re-binds
  against the store (filtered by the deterministic name, not by list position) and must
  not reflexively trigger the certbot job — inside the renewal window its guard fails
  open and spends one of Let's Encrypt's 5 duplicate certificates per 7 days. The job is
  the bootstrap path, not the recovery path.
- **The load-bearing assumption is in-place renewal** (same name → same resource id). It
  was asserted by the job's design but nothing depended on it this hard before. If it
  ever breaks, the failure is the good kind: the job's unconditional re-bind points the
  live hostnames at the new id (TLS never breaks), the declarative reference goes stale,
  and the *next apply fails loudly* — recovery is a one-line template bump. The
  verification is free and read-only: capture the cert id per install before the renewal
  window opens, diff after the renewal runs.
- **One of the two reasons a full apply is dangerous is removed.** The other — an absent
  secret rendering as `''` over the live value — is untouched, and nothing here should be
  read as making unsupervised template applies safe.
- No new telemetry: this moves control-plane declarativity, adds no runtime seam, and
  the existing TLS-expiry availability test already monitors the outcome rather than the
  mechanism.

## Amendment (2026-10-10) — one certificate and binding pair per domain

When `hostedAppsDomain` is set, the edge carries **two** wildcard custom domains on **two**
environment-store certificates. `main.bicep` computes each cert name once (`wildcard-<domain with
dashes>`) and passes it to that zone's certbot job and to its declarative edge binding.
`hostedAppsTlsBound` is the second gate beside `wildcardTlsBound` — same bootstrap semantics, same
what-if canary (`Delete properties.configuration.ingress.customDomains` must never appear for either
binding on a gated install). **Unverified in Azure:** two wildcard domains on different certificates
binding on one Container App.
