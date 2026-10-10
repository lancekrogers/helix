# 0019. Subdomain-per-app isolation with host-scoped cookies

**Status:** Accepted _(recorded retroactively 2026-06-26 — coverage audit; shipped in M2)_
**Related:** `docs/platform-architecture.md` §3 (decision #2), §4.1; ADR [0004](0004-auth-model.md), [0014](0014-same-origin-api-gateway.md); `apps/edge/src/routing/hosts.ts`, `apps/edge/src/auth/cookies.ts`

## Context

Mutually untrusted apps need separate browser origins. Path-based routing puts
all apps on one origin, allowing scripts to access shared browser storage and
other same-origin pages. A subdomain per app provides distinct origins.

## Decision

Each app is served on **its own subdomain** `<slug>.<base>`. Sessions use **`__Host-`-prefixed cookies** (host-scoped: no `Domain` attribute, `Secure`, `Path=/`), so a session cookie set for one app cannot be read by another. The **browser's same-origin policy is the isolation primitive**. A reserved set of subdomain labels (e.g. `auth`) can never be app slugs (`classifyHost`).

## Consequences

- Per-app origin isolation comes free from the browser — no app can touch another's storage, cookies, or DOM.
- `__Host-` requires HTTPS and forbids a `Domain` attribute, so a cookie genuinely cannot span subdomains — which is why crossing the boundary (login) needs an **explicit signed carrier**, the OIDC handoff (ADR-0004).
- Requires a wildcard TLS cert and DNS for `*.<base>`; custom per-app domains are rejected (they'd reintroduce origin ambiguity).
- This is the platform's most load-bearing security boundary (architecture §4.1 calls it "non-negotiable"). Reversing to path routing would collapse all apps into one origin.

## Challenge outcome (2026-06-26)

This ADR settled subdomain **vs path** routing, but not the *registrable-domain* question — and that's a real gap (filed as **#16**, Important). Untrusted apps (`*.azx.helix.azxlabs.io`), the auth host (`auth.azx.helix.azxlabs.io`), and the portal (`portal.azx.helix.azxlabs.io`) all share **one registrable domain** (`infra/azure/modules/dns.bicep`, `main.bicepparam:12`), so apps are **same-site** with the control plane — separated only at the *origin* level. Established practice (Google `googleusercontent.com`, GitHub `github.io`) is to host untrusted content on a **separate registrable domain (eTLD+1)** so the coarser *site* boundary also separates it.

Subdomain isolation + `__Host-` + Origin-checked CSRF + bearer-JWT portal close **session theft** — so this is Important, not Critical. But the shared eTLD+1 leaves residuals a separate domain would close: **cookie-bomb DoS** (`Domain=.azx.helix.azxlabs.io` → 431 on portal/auth/all apps), **Safe-Browsing / reputation blast radius** (one bad app flags the whole domain incl. the admin plane), same-site coupling with the auth host, and site-keyed storage partitioning. (The planned PSL submission partially closes the cookie vectors but not reputation.)

**Decision/amendment:** host untrusted apps on a **separate registrable domain** (`*.azx-apps.<tld>`), portal/auth on `azx.helix.azxlabs.io`. Cheap pre-M5 (DNS zone + wildcard cert + OIDC redirect URIs + verify the now-cross-site handoff, which is a signed URL token so robust); painful after customer `<slug>.azx.helix.azxlabs.io` URLs are committed. Treat as a **pre-GA prerequisite**, not an M5 blocker.

**Amendment (2026-07-22, ADR-0028):** the deployment model is now **single-tenant, customer-deployed** (ADR-0028) — the platform ships as a full instance into each customer's own cloud and domain, not a multi-tenant service we run. So #16's "a separate registrable domain **we** own" reframes to a **per-deployment topology**: within each install, untrusted apps sit on a separate *site* from that install's control plane (portal/auth/dev-api) — a delegated subdomain (e.g. `*.apps.helix.<customer>`) or a separate registrable domain the customer owns. **PSL listing of the apps zone becomes a per-deployment recommendation we document** (the customer submits it), not something we operate; the cookie-bomb / reputation / storage residuals above are then the customer's own risk *within their own namespace*, scoped by their domain choice — there is no shared cross-customer domain. This does **not** touch the ADR's core: subdomain-per-app origin isolation (`__Host-` + same-origin policy) is domain-agnostic and unchanged. It only relocates *where* the eTLD+1/site boundary is drawn — per deployment, not once for a service we host. (Our own reference deployment still carries the shared-eTLD+1 residual described above until its apps zone is split/PSL-listed; that's now a property of that one deployment, not the product.)

### Considered and rejected (2026-06-26): render apps in a sandboxed iframe (no `allow-same-origin`)

A review proposed rendering each untrusted bundle in a sandboxed `<iframe>` without `allow-same-origin` (opaque/null origin). **Rejected — don't file; category error** (5-model panel + grounding):
- A **null-origin** frame cannot ride the `__Host-` session cookie or call the same-origin `/_api/*` gateway — it **breaks ADR-0014** (the load-bearing capability choke point). Enabling `allow-same-origin` to restore those defeats the sandbox entirely.
- The sandboxed-iframe pattern (Google SafeContentFrame / double-key) is for a **trusted page embedding untrusted content**; Helix is the inverse — the untrusted app **is** the top-level navigable site (this ADR), and CSP already sets `frame-ancestors 'none'` (apps refuse framing).
- The containment that actually applies is the **separate eTLD+1 move above** (#16) + strict CSP data-flow directives + ADR-0020 (no server-side untrusted execution). Browser-side XSS in a site the user navigated to directly is the user's risk by design, bounded by origin/site isolation, not by iframe sandboxing.
- **Narrow future slice:** if the *portal* ever embeds an unpromoted app for preview inside the control plane, sandbox-without-`allow-same-origin` is the right control for *that* surface — a separate forward-compat item, not a precedent for the hosting model.

## Amendment (2026-10-10) — the apps/control split is implemented

The per-deployment site split described in the 2026-07-22 reframing is now shipped: optional
`hostedAppsDomain` / `EDGE_CONTROL_DOMAIN`, host classification, `controlOrigin`, portal
`CONTROL_PUBLIC_BASE`, optional legacy redirect, and operator rollout notes. Defaults preserve the
single-domain layout. Setting names, boot rules, PSL requirement, and what was tested locally are
recorded in the domain-split lines of [ADR-0028](0028-deployment-model-customer-deployed.md)
(Amendment 2026-10-09).
