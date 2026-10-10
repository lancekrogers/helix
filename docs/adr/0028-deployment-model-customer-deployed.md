# 0028. Deployment model: single-tenant, customer-deployed into the customer's cloud

**Status:** Accepted _(2026-07-22 — parameterizes architecture decision 11 and reframes ADR-0019 / issue #16; obligated edits applied)_
**Related:** `docs/platform-architecture.md` §3 (decisions #6, #8, #11), §9; ADR [0002](0002-postgres-role-split-rls.md) (role split — per instance), [0005](0005-ssrf-egress-controls.md) / [0013](0013-egress-trust-model.md) (egress — now guards the customer cloud), [0006](0006-secret-custody-seam.md) (secret custody — customer Key Vault), [0019](0019-subdomain-per-app-isolation.md) (subdomain/domain split — now per-deployment; issue #16), [0022](0022-self-hosted-edge-not-front-door.md) (portable self-hosted edge — this ADR's parent), [0023](0023-one-org-app-id-partitioning.md) (one-org, app-id partitioning); `docs/design/dev-mode.md`; `docs/reviews/2026-06-build-vs-buy.md` (C8)

## Context

Earlier documents assumed one hosted install at azx.helix.azxlabs.io. Helix is
instead deployed as an independent instance in each customer's cloud, with their
resources, domain, and identity provider. We do not operate customer instances.

ADR-0022 already chose a portable self-hosted data plane. This ADR makes the
customer-deployed model explicit and updates domain and deployment assumptions
that were specific to our reference install.

## Decision

**The platform is delivered as single-tenant, customer-deployed software: one complete, independent instance per customer, running in the customer's own cloud tenancy, under the customer's domain and IdP.** We ship a versioned, parameterized deployable (the M5 IaC); the customer applies it. Our own `azx.helix.azxlabs.io` install is the **reference/first deployment** of that same artifact (dogfood) — confirmed at sign-off (2026-07-22): it is strictly the reference deployment, **not** a hosted offering that coexists with customer-deployed installs. There is no hosted SaaS tier.

Concretely, each prior decision that was implicitly single-install is **parameterized, not reversed**:

1. **Base domain is a per-deployment parameter.** `EDGE_BASE_DOMAIN` — already the single knob (`apps/edge/src/config.ts`) — is set to the customer's domain (e.g. `helix.customer.com`). Decision 11's actual invariant is **preserved**: apps live at `<app>.<base>`, one canonical origin each. Per-app **vanity** domains stay rejected (they reintroduce origin ambiguity — one app at two origins). There is no "custom domains" *feature*; there is only *this deployment's* domain, and it was always config, never literally `azx.helix.azxlabs.io`.

2. **The apps ↔ control-plane site split (ADR-0019 / #16) becomes a per-deployment topology.** The separation rationale is unchanged but now **internal to each install**: within a customer's deployment, untrusted apps sit on a separate *site* from that install's portal/auth/dev-api — via a delegated subdomain (`*.apps.helix.customer.com`) or a separate registrable domain the customer owns. **PSL listing of the apps zone is a documented per-deployment recommendation** the customer submits, not something we operate. The cookie-bomb / reputation / storage residuals (#16) are the customer's own risk *within their own namespace*, scoped by their domain choice — not a cross-customer concern, because there is no shared domain.

3. **Secret custody, identity, and storage are wholly in the customer's cloud.** Their Key Vault + KEK (the ADR-0006 seam, instantiated per deployment), their Entra tenant (single-tenant OIDC), their Postgres + Blob. We never hold customer secrets, sessions, or data.

4. **Egress SSRF controls now guard the customer's cloud.** The ADR-0005/0013 blocks — private/loopback/IMDS denial, validated-IP rebind pin, no redirect-follow — protect the *customer's* metadata endpoint and internal network. A bad app reaching their IMDS is *customer* credential theft. This **raises** the stakes on those controls; they are not weakened by the deployment shift.

5. **We ship IaC, not a service.** The M5 `infra/` is a versioned artifact the customer applies; upgrades and migrations run in the customer's DB on their schedule (shipped-software lifecycle — version pinning, forward-only migrations, documented rollback), not a Container Apps deploy we push.

6. **Tenancy stays per-app within an instance (ADR-0023).** Each customer = one instance, so cross-customer isolation *is the cloud boundary itself*. `orgId`-within-an-instance remains deferred and only matters if a single customer wants internal orgs.

## Consequences

- **Strongest possible isolation.** No cross-customer blast radius exists by construction — a compromised instance is contained to one customer's cloud. This is the security high-water mark the three-plane design was already reaching for.
- **We never custody customer secrets, data, or sessions.** The trust story simplifies sharply, and a customer's data-residency / compliance requirements are satisfied by "it runs in your tenancy" rather than by contract.
- **The dev tier is per-instance and unchanged in substance.** The dev-gateway rides that instance's control-plane base (`dev-api.<control-base>`), opt-in-flaggable off (the `EDGE_ALLOW_*` mold, dev-mode §10); dev-mode's isolation thesis — the `env` partition + `helix_dev` role split — lives entirely within one instance's Postgres and is untouched. The dev-mode §10/§11 "dev-gateway hostname" guidance resolves cleanly: control-plane base of *this* deployment, never the apps zone.
- **The ops model inverts.** We own **release engineering** (versioned artifact, migration safety, upgrade docs, a CVE patch cadence customers *pull*), not runtime operations. There is no central runtime to monitor for customer instances; observability ships as part of the artifact for the customer to wire into their own stack.
- **We lose central visibility and push-fix.** No cross-customer metering rollups, no hotfixing a running customer instance — patches are pull, not push. Support telemetry becomes a shipped, opt-in concern.
- **Version skew across the fleet is now a first-class cost.** Customers run different versions; docs/ADRs describe *a* deployment, and cross-version compatibility (migration ordering, manifest schema, instruction/handoff token formats) must be explicitly versioned. This is the classic self-managed-software tax (GitLab/Retool self-hosted).
- **Edits this ADR obligates — done 2026-07-22:** architecture decision 11 (now "no per-app vanity domains; base domain is a per-deployment parameter") and the §11 resolved-note both qualified in `platform-architecture.md`; ADR-0019 carries a 2026-07-22 amendment reframing the #16 split as a per-deployment topology + PSL recommendation, not a domain we own.

## Amendment (2026-10-09): admission controls are per-install settings

The platform LLM daily ceiling, LLM and fetch in-flight concurrency caps, the install default LLM
budget when a manifest omits `dollarsPerDay`, and the wall-clock LLM call deadline are **per-install
settings**, each with a strict default and an off value where the knob allows it (the call deadline
excepted — it has no off value). A one-organization install on this model may relax or disable
individual controls without forking code. Later network-egress and domain-split work extends this same
amendment rather than adding a second one. Detail: ADR [0051](0051-llm-admission-control.md).

- **Network egress:** `egressFqdnMode`, `egressNsgEnforce`, and `EGRESS_EXTRA_BLOCKED_CIDRS` (set by the template from `vnetAddressPrefix`) are per-install settings. Unlike the admission settings, the two network modes default to the values that keep an existing install working on a template update (`any`, `deny-list-only`); the strict values (`allowlist`, `enforce`) are an operator's step once the network probe is green. See the network-controls amendment in ADR [0005](0005-ssrf-egress-controls.md).

## Considered and rejected

**Hosted multi-tenant SaaS on our cloud.** Rejected: it would place customer apps, secrets, and data in *our* tenancy (custody + residency burden), create a cross-customer blast radius, and require exactly the multi-tenant machinery this model avoids — per-tenant base-domain resolution, SNI multi-cert at a shared ingress, cross-tenant unknown-host rejection, and an `orgId` scoping layer. Not a permanent bar: recorded so that any future hosted offering is a **conscious re-decision**, not drift — and note that reversing to it later is a large re-architecture, precisely because the machinery above is deliberately absent.
