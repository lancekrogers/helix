# Security Policy

Helix is the AZX App Platform — secure hosting for vibe-coded AI apps, built on one stance:
**every hosted app is untrusted code**, contained per app rather than verified. Much of what
would be a vulnerability in an ordinary web platform is a design decision here, so please read
the scope sections below before writing a report — and know that we still very much want to
hear about anything that crosses a boundary the platform promises to hold.

> The project is beta and the security posture is still changing — that does **not** mean
> reports are unwelcome. It means we will be honest about what is a flaw, what is a documented
> residual risk, and what is already tracked.

## Reporting a vulnerability

**Report privately. Please do not open a public GitHub issue, PR, or discussion for security issues.**

Use GitHub's private vulnerability reporting (the **Report a vulnerability** button on this
repo's **Security** tab):

**<https://github.com/AZX-PBC-OSS/helix/security/advisories/new>**

Anyone can submit through that form; no GitHub special permissions are required. Please
include:

- The affected component — repo path(s), and the commit or release you tested (for the `helix`
  CLI, the published `@azx-pbc/helix-cli` version).
- Steps to reproduce, ideally a minimal PoC. For the live deployment (below), the URL and the
  app you were using.
- Impact, framed the way the platform does: which boundary does this cross — another app's
  origin or session, another user's data, an ungranted capability, a secret, the public
  internet from a component that should not reach it?
- Any deadline you are working to.

What happens next:

- We acknowledge within **2 business days** and give you an initial assessment within **7**.
- We keep you informed, and fix in a coordinated-disclosure window — please give us **90
  days** before public disclosure; ask us if you need to move sooner, and we will not hold a
  fix hostage to the calendar once a patch is out.
- The fix ships as a GitHub Security Advisory (with credit to you on the advisory) and a
  patched release; for the CLI that includes a new `@azx-pbc/helix-cli` on npm.

We are a small team without a bug bounty — we cannot offer compensation, but we will credit
you on the advisory and in the release notes.

## In scope

The platform software and our live deployment of it:

- `apps/edge` (helix-edge), `apps/portal` (helix-portal) + `apps/portal-web` (the SPA),
  `apps/egress` (helix-egress) — the three planes.
- `packages/shared`, `packages/secret-store`, `packages/telemetry`, `packages/directory`.
- The `helix` CLI (`packages/cli`, published to npm) and the deploy skill bundle
  (`packages/deploy-skill`).
- `infra/azure` — the Bicep topology (role assignments, network zones, firewall).
- Our reference deployment at `*.azx.helix.azxlabs.io` (apps), `auth.azx.helix.azxlabs.io`,
  and `portal.azx.helix.azxlabs.io`.
- A compromised or malicious runtime dependency of any platform service (supply chain).

### The surfaces we care most about

These are where the security model lives (see `docs/platform-architecture.md` §10 and
`docs/adr/` for the reasoning behind each):

- **The OIDC handoff and session machinery** (architecture §4.2 / Appendix A) — the central
  callback, the one-time handoff token (TTL, single-use, audience binding), `__Host-session`
  cookie minting, return-URL validation, silent refresh and group re-checks. The most
  security-sensitive code in the platform.
- **Cross-app isolation** — subdomain-per-app origins, host-only cookies (cookie
  tossing/shadowing), Origin validation + `form-action` at the gateway, and the block on
  app-supplied service-worker registration.
- **The serving path** — the auth gate before any asset is served, CSP injection on every app
  response, and host-routing confusion (app content reachable on the auth/portal hosts, gated
  content served without a session, version/pointer mixups).
- **Gateway authorization** — the (app, user, capability) evaluation on `/_api/*`, per-user
  RLS on app data, the write-only collections scope, BOLA on portal routes (`ownsApp`), the
  approval classifier for elevated grants, and quota/metering bypasses.
- **The edge→egress boundary** — forging, replaying, or tampering with the signed attested
  instruction; SSRF escapes in `apps/egress/src/ssrf.ts`; the secret custody seam
  (`packages/secret-store`, plaintext handling in egress); and the Postgres role split
  (`helix_edge` must never reach `app_secrets`).
- **The deploy pipeline** — bundle validation (zip handling, path traversal, type/size
  limits), version immutability, the preview-then-promote guardrail, and deploy/bearer-token
  scope (ADR-0024).

## Out of scope

- **Vulnerabilities in a hosted app.** Hosted apps are untrusted by definition — report
  problems with a specific app to that app's owner, not here. What we do want is an app
  _escaping its blast radius_: reading another app's data or session, riding another user's
  session, invoking capabilities it was not granted, reaching a secret, or reaching the
  internet from the edge. A hosted app misbehaving inside its own origin is the baseline the
  platform already assumes.
- **Relaxed CSP directives** — inline scripts/styles, event handlers, `eval`, and the curated
  CDN allowlist are deliberate (ADR-0009); containment lives in the data-flow directives
  (`connect-src`, `form-action`, `frame-ancestors`, tightened `img-src`, `object-src 'none'`).
  Navigation, popups, approved origins, request URLs to permitted CDN hosts (Hypothesis), WebRTC,
  and DNS hints remain exfil channels (architecture §10; WebRTC and DNS-hint behavior under CSP is
  untested). App code can still send out what its
  viewer can read — the platform does not claim confidentiality against a hostile app author. Misuse
  of a capability _within_ its granted scope is also a residual risk.
- **Fetch-proxy response posture** — `/_api/fetch/*` refuses worker and service-worker destination
  loads, sets `content-security-policy: default-src 'none'` on every proxied response, and strips
  `Service-Worker-Allowed` from upstream headers so only the platform offline worker route may emit
  it.
- **Dev-only stand-ins** — `apps/dev-idp` (the local OIDC issuer) and the dev AES-GCM secret
  envelope are never deployed. Only report these if the same flaw applies to the production
  path (Entra ID, Key Vault).
- **Known, tracked gaps** — before reporting a _missing_ control, check [`TODO.md`](TODO.md);
  known items include per-app RBAC (reads are still authenticated-only, ADR-0007 residual),
  confirming `deployFirewall` is on in the live deployments, and Public Suffix List
  submission. (Admin per-user session revocation shipped — the portal Sessions screen —
  and is no longer a gap.) A bypass of a control that _is_ built
  remains a valid report.
- **The usual exclusions** — volumetric DoS, unverified scanner output, social engineering,
  and spam or content problems in hosted apps.

## Testing

Please test against your own deployments or the dev container. There are not currently any
public-facing deployments.

- Use your own apps and test accounts; do not access other users' data or apps you do not
  own.
- Do not run destructive or high-volume tests against the shared Postgres/Blob backing the
  deployment.
- If you accidentally cross a boundary (someone else's data, a secret), stop, do not retain
  anything, and tell us immediately in the report.

Helix is self-hostable (ADR-0028): reports about the _software_ go here regardless of who runs
it, but testing an instance someone else deployed requires that operator's permission.
