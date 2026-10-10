# Helix on Azure — Bicep (M5)

Infrastructure-as-code for deploying the three-plane Helix platform to Azure
Container Apps. This is the `infra/` referenced in the project plan (§2) and the
"minimal IaC" of M5 (architecture §8).

> The operator-facing version of this content — install walkthrough,
> configuration reference, Entra setup — lives on the public docs site
> (`apps/docs`, deploy section). This README stays the full operational
> reference, including the deploy gotchas below; the site links here rather
> than duplicating them.

## What it provisions

| Layer    | Resources                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Network  | VNet, 5 subnets, Azure Firewall + policy, 2 route tables (forced tunnel), private DNS zones. The four private endpoints in `snet-pe` (three Key Vaults and Blob) keep **dynamic** addresses by default (`pinPrivateEndpointAddresses=false`, unchanged for existing installs). **New installs** should set `pinPrivateEndpointAddresses=true` so defaults `.4`–`.7` of that subnet (overridable via `privateEndpointAddresses`) let an egress NSG allow only the two vaults egress reads and deny the platform vault and Blob by destination IP. When pinning is off, NSG rules fall back to the whole `snet-pe` prefix (`privateEndpointSubnetPrefix` output) |
| Data     | Postgres Flexible Server (private), Storage (blob, private)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Secrets  | `kv-platform` (infra config) + `kv-connections` (app connection secrets) + `kv-delegated` (user-delegated token material, egress-only) — all private                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Identity | 4 user-assigned managed identities + the least-privilege RBAC matrix (the 4th, dev-gateway, is idle unless `deployDevGateway`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Compute  | 2 ACA environments (`apps`, `egress`) + edge / portal / egress container apps, plus the opt-in dev-gateway (`deployDevGateway`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| DNS      | public zone for the apps domain (`*`, `auth`, `portal`; `dev-api` when `deployDevGateway`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

### The security shape, in one diagram

```
                 Internet
                    │ (inbound: edge only)        ▲ (outbound: egress only)
        ┌───────────┴───────────┐                │
        │  apps env (snet-apps)  │       ┌────────┴────────────┐
        │   edge  (external)     │       │ egress env          │
        │   portal(internal)     │       │  egress (internal)  │
        │   UDR → Firewall DENY  │       │  UDR → Firewall ALLOW│
        └───────────┬───────────┘       └────────┬────────────┘
                    └──────── same VNet ──────────┘
            private endpoints → Postgres · Blob · KV×3
       (app images pulled from public GHCR, not a private registry)
```

- **edge** can be reached from the internet (public ingress) but **cannot reach
  it** — its subnet's default route goes to the firewall, which denies.
- **egress** is the only subnet the firewall lets out. It has no public ingress.
- **portal** is internal ingress only — not routable from app subdomains.
- All data services are private-endpoint only; `publicNetworkAccess` is off.
- The **edge identity has no role on `kv-connections`** — an edge RCE cannot read
  an app connection secret. (Mirrors the `helix_edge` Postgres grant hole.)
- **`kv-delegated` is egress-only** (ADR-0031):
  it holds user-delegated OAuth token material, and the egress managed identity
  is the **only** principal with any role on it (Secrets Officer — the built-in
  roles have no "set without delete", and egress must seal/open/destroy). The
  portal gets **no role**, so "the control plane never sees a plaintext
  delegated token" is enforced by RBAC absence, not convention. The
  `kv-connections` matrix is unchanged (portal Officer / egress User for
  provider client credentials).
- **dev-gateway** (opt-in, `deployDevGateway`) is the edge image run as the
  `helix_dev` role on `dev-api.<appsDomain>`, external in the apps env like the
  edge. Its identity mirrors the edge's holes — no blob, no `kv-connections` —
  and the `helix_dev` env-literal RLS keeps it off every production row. Off by
  default; see [`docs/features/dev-mode.md`](../../docs/features/dev-mode.md).

## Optional: the egress firewall (`deployFirewall`)

The Azure Firewall (Standard tier) is the enforcement point for the egress-only
network zone: it forces both app subnets' `0.0.0.0/0` through itself, **allows
only `snet-egress` out** (to any FQDN) plus a narrow platform allow-list, and
**denies the apps subnet** (edge/portal) by default. Per
[ADR-0005](../../docs/adr/0005-ssrf-egress-controls.md) this network-zone
allow-list is the **primary** SSRF/egress control; the egress app's own
`ssrf.ts` IP validation + header filtering is explicitly _defense-in-depth_
behind it (ADR [0001](../../docs/adr/0001-three-runtime-split.md),
[0013](../../docs/adr/0013-egress-trust-model.md)).

The Standard firewall deployment charge is approximately $900/month before data
processing, as estimated for this deployment. It applies even when idle.
`deployFirewall` defaults to true; operators can disable it with the security
trade-offs below.

**What you lose when `deployFirewall=false`:**

- The firewall and its forced-tunnel routes are not created; both app subnets get
  **default internet egress**. A compromised **edge can now reach the internet**
  directly, and the primary egress control is gone — only the egress app-level
  denylist (defense-in-depth, a validation surface that must be kept current)
  remains, and it only governs traffic that actually goes _through_ egress.
- The isolation guarantee in the diagram above no longer holds; the
  isolation-verification checks below invert (edge outbound **succeeds**).

**What you keep either way:** all data services stay private — Postgres, Blob,
and both Key Vaults remain private-endpoint-only (`publicNetworkAccess` disabled)
regardless of this flag. Turning the firewall off does **not** expose them.

**When off is acceptable:** dev, smoketest/integration scaffolding, or a trusted
single-tenant install where you accept the app-level denylist as the outbound
control. **When it is not:** production, or any install hosting untrusted /
multi-tenant apps — keep the firewall (or your own equivalent network egress
control). Cheaper options if you want _some_ always-on control: Azure Firewall
**Basic** (~$290/mo, same FQDN model) or — losing FQDN filtering — NAT Gateway +
NSGs. An NSG-only substitute cannot replicate the apps-subnet
posture because the platform image pulls (GHCR/MCR) require **FQDN** rules NSGs
can't express, which is why a firewall was chosen in the first place. For a
temporary install, `az network firewall deallocate` also stops the hourly charge
between test sessions without losing config.

## Azure AI Foundry (`deployFoundry`, [ADR-0046](../../docs/adr/0046-azure-ai-foundry-keyless-llm-backend.md))

By default the LLM gateway calls the first-party vendors (`api.anthropic.com`,
`api.openai.com` — keys seeded as `platform` secrets). For a customer-cloud
install where inference should bill to and stay inside the customer's
subscription, set **`deployFoundry=true`**: the template creates a dedicated
resource group for it (`<namePrefix>-foundry-rg`, `modules/foundry-rg.bicep`),
deploys one Azure AI Foundry account into it (`modules/foundry.bicep`), one
serverless deployment per model
in `foundryModels`, grants the **egress identity** the inference roles, and
points both model families at it. **Keyless — there is no vendor key anywhere:**
egress mints Entra tokens (its own managed identity, scope
`https://ai.azure.com/.default`) per call and injects them
(`EGRESS_MANAGED_IDENTITY_CONNECTIONS` is wired by the template). App code,
per-app model allowlists, and metering are unchanged — each deployment is named
for the platform catalog id (`packages/shared/src/pricing.ts`), which is what
apps request.

Things to know before flipping it:

- **`foundryAttestation` is required for Claude on a fresh subscription.** The
  Anthropic offer needs Marketplace terms acceptance; the template sends the
  attestation (`organizationName`/`countryCode`/`industry`) with every
  Anthropic deployment, which accepts it on your behalf. Without it those
  deployments fail with a terms error. (GPT models need nothing.)
- **Model availability is regional** and narrower for Claude than GPT — check
  the region's catalog before an apply, and override `foundryLocation` if the
  platform region lacks a model (a model the region lacks fails the whole
  apply). Note some Claude models run **"Hosted on Anthropic infrastructure"**
  (v1) — Azure billing, Anthropic compute. If the customer wants Azure-hosted
  compute (or Data Zone residency), restrict `foundryModels` to v2-hosted
  entries (`opus-5`, `opus-4-8`, `sonnet-5`, `haiku-4-5` at time of writing).
- **Quota is per model per subscription and auto-tiers with usage.** Fresh
  pay-as-you-go subscriptions get 40 RPM for most Claude models and Tier-1
  pools for GPT — but **`claude-sonnet-5` and the Fable line start at 0**, and
  because the deployments apply serially (`@batchSize(1)`), the first
  zero-quota entry aborts the whole apply with no hint that quota is the
  reason. That is why those models are **not in the default `foundryModels`**:
  the default is the subset of the platform catalog a fresh subscription can
  actually deploy (audited eastus2 2026-09-16; it also excludes
  Deprecating-default models — `gpt-4o-mini`, `o3`, `o4-mini`, refused outright
  — and the unverifiable `gpt-4.1` family). Every excluded model stays in the
  platform catalog and works first-party; add it back once the quota form
  lands. Increases arrive automatically with consumption, too. Deployments cost
  nothing when idle.
- **Check availability AND quota before an apply — they are different
  questions, and the catalog answers only the first.** Two read-only commands:
  `az cognitiveservices model list -l <region>` (per version, read
  `isDefaultVersion` + `lifecycleStatus`; a `Deprecating` _default_ is refused)
  and `az cognitiveservices usage list -l <region>` (read the
  `AIServices.GlobalStandard.<model>` / `OpenAI.GlobalStandard.<model>` limits;
  0 = the apply fails on that model). And when an apply does fail: the
  actionable RP error (e.g. `ServiceModelDeprecating: ...`) is buried three
  `details` levels deep in the `az deployment group create` stderr — the
  deployment-operations view shows only a tracking id.
- **The portal advertises what you deploy** (ADR-0047): on a `deployFoundry`
  install the capability catalogue, the rendered agent skill, and the model
  picker take their servable-model list from `foundryModels` automatically (the
  template derives `PORTAL_LLM_MODEL_ALLOWLIST` from it — keyless wiring seeds
  no `anthropic`/`openai` secret, so without the derivation the catalogue's
  seeded-secret heuristic would advertise nothing). Prune a model here and the
  portal stops offering it on the next apply; `llmModelAllowlist` /
  `llmModelBlocklist` override for BYO and first-party installs.
- **32 deployments per account** (Azure limit) bounds the deploy-the-catalog
  shape (~20 in the catalog today); prune `foundryModels` or shard to a second
  account (BYO wiring) if the catalog outgrows it.
- **A catalog model with no deployment 404s upstream** — the app sees a 502.
  Adding one later is a `foundryModels` edit + apply (or a portal/CLI
  deployment named for the model id); no app or edge change.
- The account deploys with **`disableLocalAuth`** (`foundryDisableLocalAuth`),
  so no usable keys exist. Set it false only to seed the account key as a
  platform secret for a dev/smoketest flow.
- **Its own resource group is the cost-axis split.** Both of Foundry's billing
  planes roll up under the account's group — GPT models meter on the account
  resource itself, Claude models bill through the Marketplace and surface as
  `<model>-<guid>` entries under the group — so the platform cost budget
  (below) never sees a token, and a separate LLM-only budget on that group
  (`modules/alerts-cost-foundry.bicep`, `llmMonthlyBudgetUsd`, default 1000 to
  match the portal's `platformMonthlyUsdCap` watch line) sees nothing else.
  Both budgets NOTIFY — Azure has no hard-spend feature for Foundry, and budget
  data runs 8–24 hours behind; the real limits are the per-app daily token
  budgets (synchronous, at the edge) and each deployment's TPM `capacity`,
  which bounds the worst-case burn rate in real time. Deployed an earlier rev
  of this branch with the account in the main group? Delete AND purge it first
  — soft-delete holds the globally-unique name for up to 48h.
- **Soft-delete holds quota for up to 48h**: deleting (not purging) a Foundry
  account keeps its TPM allocations reserved —
  `az cognitiveservices account list-deleted -o table` / `purge` to reclaim.
- Role assignments take ~5 minutes to propagate; the template declares them
  before the deployments so the provisioning time doubles as the wait, but the
  first inference call right after an apply can still 401 — retry, don't
  reconfigure.
- Networking: egress reaches the account over its public endpoint — the egress
  subnet's allow-any rule already covers it, and `disableLocalAuth` + RBAC is
  the exposure control (same class as calling first-party endpoints today). A
  private-endpoint posture is deliberately not in this template: it would
  resolve to a private IP, which the egress SSRF controls block (ADR-0046).

**BYO Foundry** (the customer already has an account, possibly in another
subscription): leave `deployFoundry` false and set the upstream params —
`llmEndpoint` + `llmOpenAiEndpoint` to `https://<account>.services.ai.azure.com`,
`llmAnthropicPath` to `/anthropic/v1/messages`, `llmOpenAiPath` to
`/openai/v1/chat/completions`, `llmAnthropicConnection`/`llmOpenAiConnection` to
your connection names (default `foundry`/`foundry-openai` keep the template's
wiring). Then either grant keyless access on your account to the egress identity
(this template outputs `egressIdentityPrincipalId`; roles: Cognitive Services
User + Cognitive Services OpenAI User) and set the
**`egressManagedIdentityConnections` parameter** —
`'foundry=<account>.services.ai.azure.com,foundry-openai=<account>.services.ai.azure.com'`
— **or** seed the account key twice (the two families take
different key headers): `seed:llm -- <key> --name foundry` and
`seed:llm -- <key> --name foundry-openai --recipe api-key`. Locally (no managed
identity), the seeded-key path is the only one — point the same env at the
account and seed as above. (Never set the egress env var out-of-band with
`az containerapp update` — the next apply silently reverts it to the param's
value.)

## Platform secret delivery ([ADR-0029](../../docs/adr/0029-platform-secret-delivery.md))

The container apps receive their **platform/bootstrap** secrets (per-role Postgres
DSNs, `EDGE_AUTH_SECRET`, the internal seam keys `HELIX_INSTRUCTION_SECRET` /
`HELIX_INTERNAL_SECRET` / `HELIX_EXCHANGE_SECRET` — one bilateral key per trust
direction) — and the
edge OIDC cert) as **ACA Key Vault references** against `kv-platform`
(`containerapp.bicep`'s
`secretValues` entries of the form `{ keyVaultUrl, identity }`). ACA resolves
them **from inside the environment's VNet** at revision-provisioning time and
materializes them into the same env vars (`secretRef`) as before — the app reads
only env vars, holds no Key Vault SDK, and stays portable across clouds. The
vault keeps `publicNetworkAccess: Disabled` throughout.

(An earlier revision of this section claimed references resolve on the ACA
control plane outside the VNet and therefore cannot reach a private vault. That
was wrong for workload-profile environments — the 2026-07 failure it was
generalized from was a private-DNS bug in this template, fixed 2026-07-29. See
the ADR's 2026-09-17 update for the evidence.)

The URIs are **versionless on purpose**: rotation is "write the vault". ACA's
background refresh picks the new value up within ~30 min (observed 22 min) and
restarts revisions itself; to rotate _immediately_, touch the app config (any
`az containerapp secret set` re-resolves all references at once). A bare
`az containerapp revision restart` does **not** re-resolve — it reuses the
snapshot stored with the revision.

The deploy-time params source from the same vault via `az.getSecret()` in the
bicepparam, so `kv-platform` is the single source of truth end to end: the
`kv-secrets` module's rewrite of each secret is an idempotent no-op, and no
secret plaintext transits the deployer's shell or CI. Two gates make that path
work, both handled by the template: the vault sets
`enabledForTemplateDeployment: true` (admits the ARM template-deployment trusted
service — the bypass survives PNA-Disabled), and the deploy principal needs
`Microsoft.KeyVault/vaults/deploy/action` (Owner/Contributor include it). Because
getSecret resolves server-side at ARM, the runner's own network position is
irrelevant. **Fresh installs are the exception:** the vault does not exist yet,
so the first applies use the env-sourced `main.bootstrap.bicepparam` (getSecret
cannot be composed with a fallback — it is a compile error anywhere but a direct
param assignment, BCP351, so the bootstrap path is a separate file, not a
ternary). Switch to `main.bicepparam` once the vault is seeded.

Two scope notes:

- **ACA Jobs cannot resolve references** (open platform bug,
  [microsoft/azure-container-apps#1804](https://github.com/microsoft/azure-container-apps/issues/1804)),
  so the migrate job keeps its runtime read of `postgres-admin-password` with its
  own managed identity. Do not move it to references until that bug closes.
- On an environment whose egress is UDR'd through the firewall
  (`deployFirewall=true`), reference resolution needs the `AzureKeyVault`
  service tag and `login.microsoft.com` on the allow list (managed-identity
  token issuance needs the Entra endpoint generally). Neither install runs the
  firewall today; add these before it comes back.

`kv-platform` is written at deploy (ARM management-plane, bypasses the firewall)
and is the canonical store. **Connection** secrets are different: they stay in
`kv-connections` and are read by egress **at runtime from inside the VNet** (a
data-plane path that works with a private vault) via the `@azx-pbc/secret-store`
seam ([ADR-0006](../../docs/adr/0006-secret-custody-seam.md)). **Delegated** token
material (user OAuth tokens) is a third thing: it lives in `kv-delegated`, same
runtime path and seam, but egress holds **Secrets Officer** there — seal at
exchange/refresh, open at resolution, destroy at retirement — and is the vault's
**only** RBAC principal (ADR-0031):
the portal has no role on it at all, so nothing in the control plane can open a
delegated token.

Egress is pointed at that vault by the template, not by an operator: it sets
`AZURE_DELEGATED_KEY_VAULT_URL` from the keyvault module's `delegatedVaultUri`
output. The same holds for the inter-app URLs — `EDGE_PORTAL_URL` on the
edge and dev-gateway (the `/connections/*` proxy and consent surfaces consult
the portal), and `PORTAL_EGRESS_URL` on the portal (the callback delegates the
vendor code exchange to egress). All three are derived from the target app's
ingress FQDN (the portal's is the `<app>.internal.<domain>` form when
`portalExternal=false`, still reachable from the shared apps environment), so
they are never set by hand — an out-of-band value is reverted by the next apply,
like any other template-managed env var.

## Wildcard TLS (`deployCertbot`, [ADR-0029](../../docs/adr/0029-platform-secret-delivery.md))

Apps live on per-app subdomains (`<app>.<appsDomain>`, ADR-0019), so serving them
over HTTPS needs a **wildcard cert** `*.<appsDomain>`. ACA managed certificates
don't do wildcards, so `deployCertbot=true` stands up **`apps/certbot`** — a
scheduled Container Apps Job (not an app/sidecar; TLS terminates at ingress) that:

1. issues/renews `*.<appsDomain>` (+ apex) from Let's Encrypt via **DNS-01**
   (`certbot-dns-azure` writes the `_acme-challenge` TXT using the job's managed
   identity — DNS Zone Contributor on the zone),
2. uploads the cert to the **ACA environment certificate store** (not Key Vault —
   the job already holds the issued PEM, and the store write is a control-plane
   call its own managed identity is authorized for) under a deterministic
   name (`wildcard-<appsDomain with dashes>`), and
3. binds the **wildcard custom domain** on the edge — plus `portal.<appsDomain>` /
   `dev-api.<appsDomain>` on their own apps when those are external. Once the
   install has flipped `wildcardTlsBound`, this bind is also **declared by the
   template** (ADR-0044 — see the bootstrap below); the job's bind steps remain as
   bootstrap and self-heal.

It renews on a daily cron. Requires `acmeEmail`; defaults to the **LE staging**
directory (`acmeServer`) — validate the flow there, then flip `acmeServer` to the
prod directory.

**Why a daily cron is safe.** The job container is ephemeral — nothing mounts
`/etc/letsencrypt` — so certbot's own "skip unless due for renewal" logic can
never fire: it always believes it has no cert. Left alone it would request a new
certificate _every run_, which outspends Let's Encrypt's duplicate-certificate
limit (**5 per identical identifier set per 7 days**, refilling 1 per 34h): a
daily schedule drains the budget in ~2.5 weeks, then fails roughly a third of its
runs — including any emergency re-issue you actually need. So the job takes its
renewal clock from the **expiry of the cert already in the environment cert
store**, the durable state it does have, and contacts the CA only within
`renewBeforeDays` (default 30) of expiry. The decision **fails open**: a missing
cert, unreadable expiry, or failed query all fall through to issuing, so the worst
case is a wasted issuance rather than a silent expiry.

The **bind** steps run on every execution regardless of that decision. They are
idempotent, and it means a scheduled run repairs bindings stripped by a template
re-apply made with the gate off (see "Known deploy gotchas") without spending an
issuance — and that they are still there to bootstrap a fresh install, where the
cert does not exist yet and nothing else can make the first bind. Once
`wildcardTlsBound=true` the bindings are declared by the template itself, so
there is nothing to strip and the job's bind steps are pure self-heal.

**Bootstrap (one-time, after deploy):** the cert must exist before the domain can
bind, so trigger the job once:

```bash
# ensure the ownership record exists (asuid TXT), then run the job:
az containerapp job start -g <rg> -n <namePrefix>-certbot
# watch it: az containerapp job execution list -g <rg> -n <namePrefix>-certbot
```

The `asuid.<appsDomain>` TXT (`domainVerificationId`) must be present for the bind
to validate — set `domainVerificationId` (read the edge app's
`customDomainVerificationId` off the deployment output; it is an `output` of the
app module) so `dns.bicep` writes it, or add it out-of-band
before the first bootstrap run.

**Then flip `wildcardTlsBound=true` in the params file and re-apply (ADR-0044).**
The cert now exists under its deterministic name, so from this apply on the
custom-domain bindings are **declared by the template** — `customDomains` on the
edge / portal / dev-gateway ingress, referencing the env-store cert by resource
id — and a re-apply **preserves** them instead of stripping them. The name is
single-sourced: `main.bicep` computes it once, feeds both the declarative
bindings and the job (injected as `CERT_NAME`), so the issuer and the reference
cannot drift. Set the flag literally in the params file, never via an env var
(a set-but-blank env var renders `''` = false, and the blank direction is the
silent-wipe one).

**The canary for the gate's state:** a what-if on a gated install must never show
`Delete properties.configuration.ingress.customDomains`. If it does, **the gate is
off — stop, do not apply.** (On a gated install the declarative set matches the
live bindings, so that Delete line is impossible unless the flag is wrong.)

## Container shutdown (graceful drain)

Every service installs a `SIGTERM`/`SIGINT` handler (`@azx-pbc/shared/lifecycle`)
that drains in-flight requests under a hard deadline and then runs its `onClose`
hooks — on a revision swap the old replica finishes short requests instead of
having every connection cut mid-byte. The deadline defaults to **10 s**
(`SHUTDOWN_GRACE_MS` overrides without a code change) and deliberately sits a
third under the Container Apps default **30 s SIGTERM-to-SIGKILL window** — the
documented contract, and the only number the platform honours reliably (its
issue tracker has cases of configured grace periods ignored and SIGTERM
undelivered on consumption profiles, so shorter-and-inside beats longer-and-hoped).

Nothing in the template sets `terminationGracePeriodSeconds` — the 30 s default
is the number the 10 s deadline sits under. Pinning it explicitly (e.g. `20`,
double the deadline) in `modules/containerapp.bicep` is optional hardening for
the next template pass, not a prerequisite; if you ever need more drain, raise
`SHUTDOWN_GRACE_MS` first and keep it comfortably under whatever the template
pins. The batch interval of the telemetry pipeline is set to 1 s precisely so
the never-delivered-signal cases lose at most a second of spans.

One runner detail the drain depends on: the images execute the entrypoint as
`node --import tsx`, **not** `tsx` — the tsx CLI installs a SIGTERM/SIGINT
handler that exits 143 outright, which would kill the process before any of
this runs. Keep the CLI out of the container CMD and the package `start`
scripts.

## Portal access (`portalExternal`, [ADR-0007](../../docs/adr/0007-portal-authz-v0.md))

The **edge** (app-serving) is public; the **portal** (control plane + `azx-cli`
target) is **internal ingress by default** — which means nobody can actually
deploy or manage anything until you make it reachable. Under
[ADR-0028](../../docs/adr/0028-deployment-model-customer-deployed.md) the customer
runs it themselves, so this can't be left as an out-of-band operator chore.

`portalExternal=true` serves the portal at `portal.<appsDomain>` on the public LB,
**gated by Entra OIDC** (portal audience + the `platform-admin` App Role), with
per-app authz enforced by `ownsApp` (ADR-0007, issue #9 closed). When set,
`portal.<appsDomain>` gets its own custom-domain binding on the wildcard cert —
runtime-bound by the certbot job until the install flips `wildcardTlsBound`,
then declared in-template (ADR-0044). The perimeter
is **identity + device posture** (Entra Conditional Access) — deliberately **not**
IP-allowlists or a bastion, which don't fit a remote team. A specific
`portal.<appsDomain>` hostname on the portal app takes precedence over the edge
wildcard in the shared environment.

Default is **false** (internal, secure-by-default); flip it per install. For a
zero-public-exposure posture instead, keep it internal and reach it via a VNet
path (VPN / Tailscale / Front Door + Private Link) — but that's friction a
customer-run, remote-team install usually doesn't want.

## Deployment topology handed to the portal SPA

The portal SPA is a **prebuilt bundle baked into the portal image**, so it cannot
know this install's domain at build time — there are deliberately no `VITE_*`
build args. It reads the topology at runtime from the public
`GET /api/v1/config`, which the template feeds via three portal env vars:

| Env var                    | Set from                                                                 | Absent means                                           |
| -------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------ |
| `APP_PUBLIC_BASE`          | `https://<appsDomain>`                                                   | **Boot failure** — the portal refuses to start in prod |
| `DEV_API_PUBLIC_BASE`      | `https://dev-api.<appsDomain>`, or `''` when `deployDevGateway` is false | The SPA says dev mode isn't enabled on this deployment |
| `PLATFORM_MONTHLY_USD_CAP` | `platformMonthlyUsdCap` (default `1000`)                                 | No spend watch line on the admin Activity page         |

`APP_PUBLIC_BASE` also drives the `url` field on every app the API returns, so a
redeployment onto a different `appsDomain` needs no client or image change.

The spend cap defaults to **$1000/mo** so an install gets a budget signal without
being configured for one; pass `platformMonthlyUsdCap=0` to show no ceiling. It is
display-only — the rollup is exact (the gateway is the choke point) but nothing
enforces it, so treat it as a watch line, not a kill-switch. Local dev leaves it
unset (no ceiling); see `.env.example`. With `deployFoundry`, the same axis gets
an Azure-side counterpart: `llmMonthlyBudgetUsd` (same $1000 default) deploys a
notify-only consumption budget on the Foundry account's own resource group — see
"Cost" under **Alerting**.

## Deploy bundle size caps

Two more portal env vars, set from template params, size what `helix deploy` will
accept. Both are in **megabytes**; unset falls back to the code default, and a
value that is present but unparseable (or `0`/negative) is a **boot failure** —
these are a security control, and a typo that silently restored the default would
be worse than a failed start.

| Env var                | Param / default               | Caps                                                                |
| ---------------------- | ----------------------------- | ------------------------------------------------------------------- |
| `DEPLOY_MAX_FILE_MB`   | `deployMaxFileMb` (**50**)    | Uncompressed bytes of any single file in the bundle                 |
| `DEPLOY_MAX_BUNDLE_MB` | `deployMaxBundleMb` (**250**) | Uncompressed bytes across the bundle, **and** the compressed upload |

Before raising `deployMaxBundleMb` much past this, note two things it interacts
with:

- **Portal temp disk.** `spoolUpload` streams the whole compressed zip to
  `os.tmpdir()` on the replica before validating it, and the portal runs at the
  `containerapp.bicep` default 0.5 CPU / 1 Gi — roughly 2 GiB of ephemeral storage,
  shared across concurrent deploys. Raise `cpuCores`/`memory` alongside the cap.
- **The CLI buffers the zip in memory.** `packages/cli/src/zip.ts` builds the
  archive with `Buffer.concat`, so peak CLI memory is about 2× the zip. That, not
  the server, is what a very large bundle hits first.

Raising the per-file cap does **not** widen what _types_ are accepted —
`apps/portal/src/deploy/mime.ts` is a static-asset allowlist with no video or
audio types, so a large `.mp4` is rejected on type regardless of size.

## Fetch-proxy body cap

`fetchMaxBodyMb` (default **25**) caps each direction of a `/_api/fetch` call:
the request body the app sends and the response body the target returns. One
value feeds both hops. The template converts it to bytes and sets it as
`EDGE_FETCH_MAX_BODY_BYTES` on the edge and the dev gateway, and as
`EGRESS_MAX_BODY_BYTES` on egress. Each hop enforces it on its own, so a hop
left at the 10 MiB code default still answers 413 above that.

Bodies are streamed through a byte counter, not buffered, so raising the cap
does not raise per-request memory. It does let each call move more bytes and
hold its connection open longer, still within the 120 s fetch timeout.

Neither service validates the value at boot: a malformed one becomes `NaN`.
The param's `int` type and `@minValue(1)` are the guard, so set the cap through
the param rather than by hand on a container app. The default of 25 matches the
25 MB upload limit on OpenAI-style `/audio/transcriptions` endpoints; see
[`docs/runbooks/raise-fetch-body-cap.md`](../../docs/runbooks/raise-fetch-body-cap.md).

## Layout

```
main.bicep            orchestrator (resourceGroup scope)
main.bicepparam       parameters (resource names + secrets via env vars)
modules/
  network.bicep       VNet + subnets + delegations
  routing.bicep       2 empty route tables (routes added by firewall.bicep)
  firewall.bicep      Azure Firewall + policy + default routes
  privatedns.bicep    private DNS zones + VNet links
  private-endpoint.bicep  reusable PE + DNS zone group
  storage.bicep       storage account + app-bundles container + PE
  keyvault.bicep      kv-platform + kv-connections + kv-delegated + PEs
  postgres.bicep      Flexible Server (private) + helix DB
  identity.bicep      4 user-assigned managed identities (edge/portal/egress + dev-gateway)
  rbac.bicep          role assignments (the grant matrix)
  foundry-rg.bicep    the Foundry account's own resource group (the cost-axis split) with foundry.bicep in it (deployFoundry, ADR-0046)
  foundry.bicep       Azure AI Foundry account + model deployments (invoked by foundry-rg.bicep)
  aca-environment.bicep   reusable managed environment (called twice)
  containerapp.bicep  reusable container app (edge/portal/egress + opt-in dev-gateway)
  dns.bicep           public DNS zone + records (incl. opt-in dev-api)
```

Production Dockerfiles for the three apps live next to their source
(`apps/edge/Dockerfile`, `apps/portal/Dockerfile`, `apps/egress/Dockerfile`);
build them from the **repo root** (the build context is the whole pnpm
workspace).

## Deploy

Prereqs: `az` CLI logged in, a target subscription, and a resource group. On a
fresh subscription, register the resource providers first — the deploy fails
on an unregistered namespace:

```bash
for ns in Microsoft.App Microsoft.Storage Microsoft.OperationalInsights \
          Microsoft.DBforPostgreSQL; do
  az provider register -n "$ns"
done
# add Microsoft.CognitiveServices if you plan to use deployFoundry
```

And check Postgres SKU availability in the chosen region **for that
subscription** before committing to it — restrictions are per subscription,
not per region, so a region one subscription can use may be refused for
another:

```bash
az postgres flexible-server list-skus -l <region>
# a `reason` field on the first element means restricted — pick another region
```

Same for compute quota: the deploy creates **two Container Apps environments**
(apps + egress) in that region, and a fresh or trial subscription can default
below that — which fails the second environment mid-apply:

```bash
SUB=$(az account show --query id -o tsv)  # current login; or a literal id
REGION=<region>                           # the deploy region

az rest --method get \
  --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.App/locations/$REGION/usages?api-version=2025-07-01" \
  --query "value[?name.value=='ManagedEnvironmentCount']"
# limit - currentValue must be >= 2
# (cores are environment-scoped, not regional — the per-environment
# default covers this platform, which idles under 5)
```

An increase is a portal **Quotas** blade request (provider _Azure Container
Apps_ → _Managed Environment Count_) — usually approved in minutes, but it
can take days, so check before you need it. (Command verified against a live
subscription 2026-09-18; the unfiltered response also carries GPU,
session-pool and sandbox quotas the platform doesn't use.)

### 1. Validate / preview

```bash
cd infra/azure
az bicep build --file main.bicep                 # compile check
az deployment group what-if \
  -g <rg> -f main.bicep -p main.bicepparam        # preview
```

The compile check also runs in CI on every PR — the `bicep` job in
`.github/workflows/ci.yml` builds `main.bicep`, `main.bicepparam` and
`infra/entra/main.bicep`. It shares nothing with the node jobs and gates
nothing. `what-if` stays a manual step: it needs a live subscription.

**Check your environment for a stale `HELIX_EDGE_TRUST_PROXY`.** It used to hold
the ACA ingress **hop count** (`1`); fastify 5.12.1 deleted that form
(GHSA-3m5p-2c4r-xxw2, ADR-0011's 2026-09 amendment) and `edgeTrustProxy` now
names the ingress **address**. A count still exported here is rejected by the
template — but check it by eye now (`echo "$HELIX_EDGE_TRUST_PROXY"`; anything
numeric is the stale form — `0` is tolerated with its old meaning, trust
nothing, but clean it up anyway), because **the `what-if` above will not catch
it**. The guard sits in the expression feeding the two `EDGE_TRUST_PROXY` sites,
and both are inside `deployApps`-conditional resources, so an infra-only pass
(`deployApps=false`, the bicepparam default) never evaluates it: the deployment
aborts at **step 5**, after you have built images and run migrations. That is
still ahead of the container, which is the point: left unvalidated the count
would reach `EDGE_TRUST_PROXY` and crash the edge at boot, and under
`activeRevisionsMode: 'Single'` the old revision keeps serving a rollout that
never takes. `true` is rejected at deploy alongside the counts — it trusts
every peer, so anyone reaching the edge directly sets its own `req.ip`, the
spoofing the hop-count removal closed. Remove a stale export with the literal
`unset HELIX_EDGE_TRUST_PROXY`, not a blank `HELIX_EDGE_TRUST_PROXY=` line in a
sourced `.env` — a blank export resolves to `auto` too (the bicepparam
normalizes it), so that spelling is harmless, but unset is the clean state — or
set it to `auto`, which trusts the ACA ingress at `100.64.0.0/10` — the RFC 6598
shared address space its pods are drawn from, **not** the apps subnet the edge
runs in (measured 2026-09-03; ADR-0011's 2026-09 amendment). Set an address only
when something else fronts the edge (CDN, WAF), and re-verify `req.ip` against
the live deployment when you do — see
[Verifying the trusted-proxy address](#verifying-the-trusted-proxy-address)
below for how.

### 2. Phase 1 — infra only (`deployApps=false`)

Set the secret env vars, then deploy. The apps are skipped on this pass.

> **Use `main.bootstrap.bicepparam` while the vault does not exist yet.** Steady
> state sources every secret from `kv-platform` via `az.getSecret()`
> (`main.bicepparam` — see "Platform secret delivery"), which cannot run before
> the first apply has created and seeded the vault, and cannot be composed with
> an env-var fallback (BCP351) — hence the separate bootstrap file rather than a
> ternary. Keep using it through the first `deployApps=true` apply (the one that
> seeds the vault), then switch to `main.bicepparam` and drop the secret
> exports.

```bash
# DB passwords are interpolated into DSN URLs (see the *DbConn vars in
# main.bicep), so they must be base64URL — a plain base64 value containing
# / + = corrupts the DSN it lands in.
export HELIX_PG_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')
export HELIX_EDGE_DB_PASSWORD=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')
export HELIX_PORTAL_DB_PASSWORD=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')   # helix_portal runtime role (role created in step 4)
export HELIX_EGRESS_DB_PASSWORD=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')
export HELIX_DEV_DB_PASSWORD=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')     # helix_dev role — create it now even if deployDevGateway stays false (see step 4)
# Signing secrets are base64-DECODED by the apps — standard base64 here.
# A base64url value makes the edge crash on boot.
export HELIX_EDGE_AUTH_SECRET=$(openssl rand -base64 48)
export HELIX_PORTAL_SECRET=$(openssl rand -base64 48)
export HELIX_INSTRUCTION_SECRET=$(openssl rand -base64 48)
export HELIX_INTERNAL_SECRET=$(openssl rand -base64 48)
export HELIX_EXCHANGE_SECRET=$(openssl rand -base64 48)
# Edge auth is a CERTIFICATE (private_key_jwt) — the tenant blocks client secrets.
# Upload the public cert to the edge app registration; feed both PEMs here (base64
# avoids multiline env headaches). See docs/runbooks/entra-app-registration.md.
export HELIX_EDGE_OIDC_PRIVATE_KEY=$(base64 -w0 edge-key.pem)
export HELIX_EDGE_OIDC_CERTIFICATE=$(base64 -w0 edge-cert.pem)
export HELIX_EDGE_OIDC_CLIENT_ID=<helix-edge client id (GUID)>
export HELIX_PORTAL_OIDC_AUDIENCE=<helix-portal client id (BARE GUID — v2 token aud)>
export HELIX_PORTAL_ADMIN_GROUP_ID=platform-admin   # the App Role value, not a group id
export HELIX_AZX_CLI_CLIENT_ID=<azx-cli client id (GUID)>
export HELIX_AZX_WEB_CLIENT_ID=<helix-portal client id (GUID)>

az deployment group create -g <rg> -f main.bicep -p main.bootstrap.bicepparam
```

### 3. Build + publish the three images

CI builds and publishes all three images to **GHCR** on pushes to the default
branch and on `v*` tags (`.github/workflows/ci.yml`):

```
ghcr.io/azx-pbc-oss/helix-edge:<tag>
ghcr.io/azx-pbc-oss/helix-portal:<tag>
ghcr.io/azx-pbc-oss/helix-egress:<tag>
```

Tags produced per push: the branch name, the commit SHA (`sha-<short>`), the
semver on `v*` tags, and `latest` on the default branch. The container apps pull
these directly (see `imageRegistry` / `imageTag` in `main.bicepparam`), so a
normal deploy needs no local build — set `imageTag` to the tag CI published and
run the deployment.

> **GHCR packages must be pullable by the deploy.** The bicep does an anonymous
> pull by default (empty `registries`), which requires the three packages to be
> **public** (Package settings → Change visibility → Public — the repo can be
> public while packages default to private). To keep them private instead, pass
> a `registries` entry to the container apps (a `{ server: 'ghcr.io', username,
passwordSecretRef }` with a `read:packages` PAT) and provision that secret.

To build/publish manually (e.g. off-CI), from the repo root:

```bash
echo "$GHCR_PAT" | docker login ghcr.io -u <github-user> --password-stdin
REG=ghcr.io/azx-pbc-oss
docker build -f apps/edge/Dockerfile   -t $REG/helix-edge:$TAG   .
docker build -f apps/portal/Dockerfile -t $REG/helix-portal:$TAG .
docker build -f apps/egress/Dockerfile -t $REG/helix-egress:$TAG .
docker push $REG/helix-edge:$TAG && docker push $REG/helix-portal:$TAG && docker push $REG/helix-egress:$TAG
```

### 4. Create the Postgres runtime roles

The server and `helix` DB exist; the least-privilege roles and grants do not
yet. The committed role SQL (`sql/01-roles.sql` — the prod analog of
`.devcontainer/db-init/01-roles.sql`, with `NOBYPASSRLS` explicit on all four
roles) creates them, run once as the admin with the **same passwords** you set
above. It must run before the first migration: the migrations' per-table GRANTs
are guarded by an `IF EXISTS role` check, so the roles must exist first.

Postgres is private-endpoint-only, so this runs as a throwaway Container Apps
Job inside the VNet — `scripts/create-roles.sh` wraps the whole operation
(build the job via `az rest`, run the SQL in it, poll, then delete the job,
which it must not survive: it carries the admin DSN as a job secret):

```bash
RG=<rg> PREFIX=<namePrefix> scripts/create-roles.sh
```

It reads the same `HELIX_*` env vars as the bicepparam, and it is **run-once**:
`CREATE ROLE` is not idempotent, and a second run fails with "role already
exists". To change a role password later, `ALTER ROLE` through the same
throwaway-job shape — don't re-run the script.

> Create `helix_dev` here even if you are not deploying the dev-gateway
> (`deployDevGateway=false`) — the role is harmless without its app, and adding
> it later means re-running the migration to pick up its guarded grants + RLS.
> The script always creates all four; just don't skip `HELIX_DEV_DB_PASSWORD`.

This is the only step that places the admin credential on a resource. The first
migration is step 6 below, after the apps apply — and it already uses the
credential-free migrate job.

> **Note:** every container runtime connects as its least-privilege role
> (`helix_portal` / `helix_edge` / `helix_egress`, and `helix_dev` for the
> dev-gateway) — the portal reads `PORTAL_DATABASE_URL` and, under
> `NODE_ENV=production`, refuses the `DATABASE_URL` owner fallback (ADR-0002).
> The admin DSN is never placed in a long-lived container.

#### Every migration: the `<namePrefix>-migrate` job

All migrations — **including the first** — are applied by the
`<namePrefix>-migrate` Container Apps Job (`modules/migrate-job.bicep`), which
`deployApps=true` creates. That gating is why the fresh-install order is roles
→ apps apply → migrate: on the first `deployApps=true` pass the apps boot
before the schema exists (they answer `/health` and fail real requests until
the migration lands — expected), and the migrate job appears alongside them.

```bash
az containerapp job update -g <rg> -n <namePrefix>-migrate --image <registry>/helix-portal:<tag>
az containerapp job start  -g <rg> -n <namePrefix>-migrate
# then confirm the execution succeeded — a started job is not a finished one:
az containerapp job execution list -g <rg> -n <namePrefix>-migrate \
  --query "[0].{name:name,status:properties.status,start:properties.startTime}"
```

The job runs the portal image inside the VNet — needed either way, since Postgres
is private-endpoint-only — and resolves the admin password itself: it reads the
`postgres-admin-password` secret from `kv-platform` using a deploy-scoped managed
identity whose only permission is `Key Vault Secrets User` on that vault
(`apps/portal/scripts/migrate-deploy.ts`). So no pipeline, and no ARM resource,
has to hold the schema-owner credential, and there is nothing to delete after a
run.

That secret is written by `kv-secrets.bicep` from the same `postgresAdminPassword`
parameter that provisions the server, so one apply sets both and they cannot
drift. Rotating the admin password out-of-band (e.g.
`az postgres flexible-server update --admin-password`) **will** drift from the
stored copy and break the job — change the parameter and re-apply instead.

### 5. Phase 2 — deploy the apps (`deployApps=true`)

Still the bootstrap file here — this is the pass that seeds `kv-platform`:

```bash
export HELIX_IMAGE_TAG=$TAG
az deployment group create -g <rg> -f main.bicep -p main.bootstrap.bicepparam \
  --parameters deployApps=true
```

From the NEXT apply on, use `main.bicepparam` (vault-sourced secrets; no
`HELIX_*` secret exports — only the non-secret ids and `HELIX_IMAGE_TAG` stay
env-sourced). The vault carries `enabledForTemplateDeployment` from its first
creation, so nothing else has to change hands.

This pass also creates the `<namePrefix>-migrate` job (step 6 runs it). The
apps boot before the schema exists — they answer `/health` and fail real
requests until the first migration lands. Expected on a fresh install, and
invisible from outside: DNS isn't delegated until step 7.

#### (Optional) the dev-gateway

The opt-in dev-mode surface (`dev-api.<appsDomain>`) is off by default. To stand
it up, add `deployDevGateway=true` (it shares the edge image, so no extra build):

```bash
az deployment group create -g <rg> -f main.bicep -p main.bicepparam \
  --parameters deployApps=true deployDevGateway=true
```

Before enabling it on a real deployment, read the riders in
[`docs/features/dev-mode.md`](../../docs/features/dev-mode.md): a **short-window
throttle** on the dev-gateway itself, a **distinct dev LLM budget** (the vendor
key is env-agnostic), and the `dev-api` DNS/TLS binding (step 7, added when this
flag is set). The `edgeTrustProxy` trusted-ingress address is passed to this
container too, and since 2026-09-03 it is a **correct** address rather than
merely a passed one, so it is no longer one of the riders (issue #13). Passing it
was never the hard part; having it be right was.

#### Verifying the trusted-proxy address

**The primary check is automatic since 2026-09-23 (ADR-0011):** the edge's `/health` carries a
`trust-proxy` sub-check that degrades once 50 forwarded-header requests have arrived and **none**
resolved `req.ip` past the socket peer — i.e. exactly the failure this section used to require a
manual session to find. The `helix.edge.trust_proxy.unresolved` gauge and its alert rule in
`modules/alerts.bicep` make the same condition page. Read the check on
`https://auth.<domain>/health` (a platform host — on app hosts `/health` is an asset path), or
just rely on the alert: the availability probes keep the window full on their own.

Do the manual recipe below only when a degraded report needs confirming, or when working without
telemetry — and after any rollout that changes `edgeTrustProxy`, and after anything new is put in
front of the edge. `req.ip` behind ACA's Envoy ingress is only the real client if
`EDGE_TRUST_PROXY` names the address the ingress presents — and when it doesn't, the trust walk
truncates at the socket peer, the anon limiter / login throttle / audit hash collapse to one
bucket per app, and (before the check existed) `/health` stayed green. That is how the wrong
default (the apps subnet) survived from M5 to 2026-09-03.

`rate_counters.bucketKey` is plaintext `<purpose>:<ip>:<appId>` (`counterStore.ts`)
and Postgres is private-endpoint-only, so read it from inside the VNet with a
throwaway job carrying the least-privilege `helix_edge` DSN as a `secretRef` (the
`set-role-password.sh` shape). Generate known traffic first — a few failed
`POST /_auth/login` against a password app, since the throttle is reserve-first
and counts failures — then query inside the 5-minute window before the sweep:

```sql
SELECT "bucketKey", count, "resetAt" FROM rate_counters
WHERE "bucketKey" LIKE 'anon:%' OR "bucketKey" LIKE 'login:%'
ORDER BY "resetAt" DESC LIMIT 50;
```

The key carries the client's address → correct. Anything else — an ACA ingress
pod (`100.100.x.x`), an apps-subnet address (`10.0.2.x`) — → the walk is still
truncating at the peer.

Two traps. `(0 rows)` means no traffic inside the live window, not a failure: the
rows expire. And a CSRF-refused POST returns 403 **before** the throttle reserve,
so it creates no row at all — a `curl` with no `Origin` header passes that check
by design (`isSameOriginFormPost`) and does count.

### 6. Run the first migration

The apps apply created the `<namePrefix>-migrate` job — run it now, exactly as
in "Every migration" above (pin the image to the tag being deployed, start it,
confirm the execution reports `Succeeded`). Apps that booted before the schema
existed pick it up on their own; nothing needs restarting.

### 7. DNS + TLS

- Delegate `azx.helix.azxlabs.io` (a subdomain of `azxlabs.io`) by adding NS
  records for `azx.helix` in the parent `azxlabs.io` Cloudflare zone, pointing at
  the deployment output `dnsNameServers` — not at the registrar.
- Bind the wildcard cert (`*.azx.helix.azxlabs.io`) and ACA custom domains — the
  `deployCertbot` job does this (see "Wildcard TLS"). Supply
  `domainVerificationId` to write the `asuid` TXT record ACA needs.
  A custom-domain binding is **per container app**, so the job binds each plane
  that has its own external ingress: the edge wildcard always, plus
  `portal.<appsDomain>` when `portalExternal` and `dev-api.<appsDomain>` when
  `deployDevGateway`. Nothing to bind by hand.
- **Delegation must exist before the first certbot run** — Let's Encrypt has to
  resolve the DNS-01 TXT in the Azure zone publicly, so a cert issued before the
  NS records propagate will fail validation.

## Telemetry (ADR-0037)

Services speak **OTLP and nothing else**; the Azure knowledge lives entirely in
this directory. `deployTelemetry` (default `true`, requires `deployApps`) adds:

- a **workspace-based Application Insights** component attached to the apps
  environment's existing Log Analytics workspace, so a trace and the log lines
  around it are in one place with one retention setting;
- an **`otel-collector` container app per managed environment** — internal
  ingress, OTLP/HTTP on 4318 — both exporting to that one component, so a trace
  crossing edge → egress still lands together;
- **the alert rules** (`deployAlerts`, `deployAvailabilityTests`) that consume it
  — see "Alerting" below.

Each service gets `OTEL_EXPORTER_OTLP_ENDPOINT` pointing at its own
environment's collector. With `deployTelemetry=false` the var is empty and
`startTelemetry` returns its inert handle — the platform's documented default
state, not a broken one.

### Two things to know before you touch this

**The managed OpenTelemetry agent was rejected, not overlooked.** ADR-0037
decision 2 preferred it; it was verified on 2026-09-01 and fails on two counts
(ADR Amendment 7): its Application Insights destination does not accept metrics,
and it only speaks gRPC while the services export OTLP/HTTP. Re-proposing it
means arguing with that.

**Metrics go to Application Insights too, in `customMetrics`.** Amendment 7
originally said App Insights could not store them; that was true of the
**managed agent's** destination and over-generalised (Amendment 8). The
collector's own `azuremonitor` exporter handles all three signals, so the
metrics pipeline exports there and the `nop` is gone. An Azure Monitor
workspace remains the better long-term store — metric alert rules and Grafana
key on a Prometheus store rather than a log-based table — and is tracked in
`TODO.md` as a strictly additive change. It is not free: it authenticates with
Entra, which would turn the collector's image-pull identity into an
authorization principal and widen the **edge's** identity unless the collector
gets its own.

## Alerting (`deployAlerts`, `alertEmails`)

Five modules, split by **what they read** rather than by what they are about,
because that is what decides which failures a rule can see at all:

| Module                      | Reads                         | Needs `deployTelemetry` | Gate                               |
| --------------------------- | ----------------------------- | ----------------------- | ---------------------------------- |
| `alerts.bicep`              | the platform's own telemetry  | yes (metric rule)       | `deployAlerts`                     |
| `alerts-availability.bicep` | an outside HTTP probe         | yes (App Insights)      | `deployAvailabilityTests`          |
| `alerts-infra.bicep`        | Azure platform metrics        | no                      | `deployInfraAlerts`                |
| `alerts-cost.bicep`         | billing (the platform groups) | no                      | `deployCostBudget`                 |
| `alerts-cost-foundry.bicep` | billing (the Foundry group)   | no                      | `deployCostBudget`+`deployFoundry` |

The first three notify through **one** action group (`modules/action-group.bicep`,
`<prefix>-ag-platform`), so a recipient is added in one parameter rather than
five files. The budgets are the exceptions and say why in their own headers.

### The platform's own telemetry (`modules/alerts.bicep`)

The consumer ADR-0025 was waiting for. Three rules, on **different signals on
purpose**:

| Rule                           | Reads                                                             | Why not the other signal                                                                                                                                                 |
| ------------------------------ | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `-alert-registry-stale`        | the `helix.registry.stale_for_ms` metric, over `AppMetrics`       | An age wants a threshold; this is what replaced KQL over log messages                                                                                                    |
| `-alert-registry-never-loaded` | the `registry.never_loaded` log event                             | The gauge is _absent_ in that state by design, and the counter that reports it is cumulative — a threshold on it would never stop firing                                 |
| `-alert-trust-proxy`           | the `helix.edge.trust_proxy.unresolved` metric, over `AppMetrics` | The trust-proxy `/health` sub-check grades `degraded`, which no other rule reads — without this rule the edge's `EDGE_TRUST_PROXY` self-report reaches nobody (ADR-0011) |

Both scope to the apps environment's Log Analytics workspace, which holds the
container stdout **and** the metrics (the component is workspace-based onto it).
Note the metric rule queries `AppMetrics`, not `customMetrics`: same table, two
schemas, and a workspace-scoped rule sees the workspace one. The workspace
schema also **dropped the `value` column** — rows carry `Sum`/`ItemCount`/
`Min`/`Max` — so a query written against `value` matches nothing, silently.

```bash
# multiple recipients; each becomes its own email receiver on one action group
az deployment group create -g <rg> -f main.bicep -p main.bicepparam \
  --parameters deployApps=true \
               alertEmails='["ops@example.com","oncall@example.com"]'
```

`registryStalenessThresholdMs` defaults to `1200000` — the ADR-0025 **error**
line (20× the 60 s reconcile interval). Drop it to `300000` to fire at the
_degraded_ line instead, and expect noise from transient DB blips.

**With `alertEmails` empty the rules still deploy and still fire — at nobody.**
That state looks identical to working alerting, so the deployment emits an
`alertsNotify` output saying which one you got. Read it.

### Availability tests — the only view from outside (`modules/alerts-availability.bicep`)

Every other rule reads something the platform said about itself, and they share
one blind spot: a platform that is not running says nothing, and silence looks
like health. `deployAvailabilityTests` (default `true`, needs `deployTelemetry`)
adds an Application Insights **standard test** per public endpoint plus the
metric alert that notifies on it.

Standard tests, not the old free URL ping tests — **those retire 30 September
2026** and existing ones are deleted from the resource. Standard tests are billed
per execution; five locations every five minutes is ~43k executions/month per
URL, which is what `availabilityTestFrequencySeconds` and
`availabilityTestLocations` control.

| Probed                                    | When                                                                      |
| ----------------------------------------- | ------------------------------------------------------------------------- |
| `https://auth.<appsDomain>/health`        | always                                                                    |
| `https://portal.<appsDomain>/health`      | `portalExternal=true`                                                     |
| whatever `availabilityExtraTargets` lists | e.g. a real hosted app, which is the only way to cover Blob asset serving |

Three things about that table are load-bearing:

- **The edge is probed on the AUTH host.** `/health` on an _app_ host serves app
  content by design (the host router mounts platform routes on platform hosts
  only), so `auth.<appsDomain>` is the one public hostname that answers the
  platform health JSON.
- **`dev-api.<appsDomain>` is never probed**, even with the dev-gateway deployed:
  `dev-api` is a valid app slug and is not in `RESERVED_SUBDOMAINS`, so the edge
  image classifies that host as an app and serves assets from it. A probe there
  gets a 404, not a health body.
- **Egress cannot be probed at all** — internal-only environment, no public load
  balancer. That is ADR-0001 working, not a gap. Its liveness is inferred from
  the edge's fetch-proxy spans.

**It reads the body, which is the whole point.** `/health` answers 200 in every
state on purpose (ADR-0025 — a non-200 would let a liveness probe restart a
replica serving correctly from a stale projection), which is exactly why no ACA
probe can grade it. The test's content validation fails on
`"status":"error"` in the body (`availabilityExtraTargets` URLs get the same rule;
a string that never appears simply never fails). `degraded` is deliberately not
matched — the staleness rule already owns that condition from the inside.

**TLS: the check follows `acmeServer`.** `availabilityTlsCheck` defaults to
`false` while `acmeServer` is the Let's Encrypt **staging** directory (the
template default), because a staging cert chains to an untrusted root and every
probe would fail on the certificate instead of telling you anything about the
platform. Point `acmeServer` at production and it turns itself on — and with it
`availabilityTlsExpiryWarningDays` (14), which is the cheapest possible monitor
on ADR-0029's certbot job: the job renewing is the mechanism, a certificate with
days left is the outcome, and a job that succeeds while renewing the wrong thing
is the failure that otherwise gets missed.

`availabilityFailedLocationCount` (3 of 5) follows Azure's guidance of
(locations − 2). It is **clamped** to the number of locations, because a
threshold above that is a rule that can never fire — indistinguishable from a
healthy platform.

### Infrastructure (`modules/alerts-infra.bicep`)

Azure platform metrics, so these need neither the collector nor App Insights and
work on an install running with `deployTelemetry=false`.

| Rule                      | Reads                                                        | Sev | Note                                                                                                             |
| ------------------------- | ------------------------------------------------------------ | --- | ---------------------------------------------------------------------------------------------------------------- |
| `-alert-db-unavailable`   | `is_db_alive` < 1, Max over 5 min                            | 0   | The only severity 0. Cannot see a **stopped or deleted** server — a metric rule cannot fire on absence           |
| `-alert-db-storage`       | `storage_percent` > 85, Avg over 15 min                      | 2   | A full server stops accepting writes, and growing the disk is a maintenance operation                            |
| `-alert-replica-restarts` | `RestartCount` > 3, Max over 15 min                          | 2   | One multi-resource rule over all container apps. **The metric is cumulative per replica** — see below            |
| `-alert-edge-5xx`         | `Requests` where `statusCodeCategory` is 5xx, > 100 / 15 min | 2   | The edge fronts untrusted app code, so one broken app is not a platform incident                                 |
| `-alert-service-health`   | Service Health activity log                                  | —   | Incidents + planned maintenance. Free. Needs an action group; Azure rejects an activity-log alert with no action |

Two caveats worth knowing before you tune them:

- **`RestartCount` is cumulative for the life of a replica** ("the cumulative
  number of times the replica has restarted since it was created"). Aggregated
  with Max, a replica that restarted 4 times and then settled holds the rule open
  until that replica is replaced — it does not self-clear the way a rate would.
  That is why the threshold is a storm number (Azure's own baseline guidance) and
  the severity is 2.
- **The Service Health rule is subscription-scoped**, because Service Health
  events are not attached to individual resources. On a shared subscription
  expect events about services Helix does not use; narrow it by impacted service
  in the portal if that becomes noise.

### Cost (`modules/alerts-cost.bicep`)

A monthly consumption budget on this resource group, notifying at 80% actual,
100% actual and 100% **forecast**. Skipped when `alertEmails` is empty, and
**not** gated on `deployApps`: the expensive resources exist after phase 1, so it
is worth having before any app is deployed. It **notifies and does not enforce** —
Azure will not stop a resource when a budget is crossed. The real limits are the
per-app daily LLM budgets and the **enforced platform daily ceiling** on the edge
(`EDGE_LLM_PLATFORM_DOLLARS_PER_DAY`, Bicep `llmPlatformDollarsPerDay`, default
`max(platformMonthlyUsdCap / 10, 3 × llmDefaultDollarsPerDay)` per day). That ceiling is not this
Azure budget — it is spend refused at
the gateway when the day's ledger sum crosses the install setting. Operator rollout:
`apps/docs/src/deploy/updates.md` ("Upgrading to the LLM spend controls").

**LLM spend is a separate axis and is never in this budget.** With vendor-direct
keys it is not in Azure at all; with `deployFoundry` it bills into the Foundry
account's _own_ resource group (the split is topological — budget filters are
AND-of-`In` only and cannot express an exclusion), where
`modules/alerts-cost-foundry.bicep` watches it instead. That budget takes
`llmMonthlyBudgetUsd` as a **direct amount**, not a derivation: the headroom
arithmetic below exists because fixed-cost month-to-date is a straight line,
and LLM spend is usage-shaped — set the monthly number you actually want mail
about. It defaults to `1000`, the same line `platformMonthlyUsdCap` renders on
the Activity page, and carries the same notify-only caveat, louder: the cost
data it reads lands 8–24 hours late, so a runaway app is stopped by the per-app
daily token budgets and the deployments' TPM capacity, not by this.

**The amount is derived from the deployment shape, and `deployFirewall` is 88% of
it.** Azure Firewall Standard bills $1.25 per hour of _deployment time_ — flat,
so an idle firewall costs what a busy one does — plus its static public IP,
before $0.016/GB of data processing (rounding error at this platform's volumes):

| `deployFirewall` | Baseline | Firewall | Expected  | Budget at 160% | 80% notification |
| ---------------- | -------- | -------- | --------- | -------------- | ---------------- |
| `false`          | ~$125    | —        | ~$125/mo  | $200           | $160             |
| `true`           | ~$125    | ~$920    | ~$1045/mo | $1672          | $1337            |

That is an 8× swing, so no single hardcoded amount is right for both shapes:
sized for the small install it fires on day three of every firewall month, and
sized for the firewall it never fires on the small one.
`expectedMonthlyUsdExFirewall` (125) and `firewallMonthlyUsd` (920) are the two
inputs; `monthlyCostBudgetUsd` overrides the whole derivation.

**Why the budget is not the expected bill.** An `Actual` notification compares
_month-to-date_ spend against the amount, and month-to-date spend on a healthy
install is a straight line from zero to the monthly total. Set the budget to
expected spend and 80% of it is reached four fifths of the way through the month:
**the 24th, every month, forever, with nothing wrong.** That teaches the reader to
delete the mail unread, which is the one mail that has to be read the month
something is actually wrong. `budgetHeadroomPercent` (160) is what puts the
thresholds back on the cost axis:

| Notification  | Means                                                            |
| ------------- | ---------------------------------------------------------------- |
| 80% actual    | 128% of expected — meaningfully over                             |
| 100% actual   | 160% of expected — well over, this month                         |
| 100% forecast | the run rate projects past 160% of expected, early enough to act |

Below ~125% headroom the actual thresholds degenerate back into that monthly
reminder. The forecast notification needs cost history to project a run rate, so
on a brand-new subscription it can stay quiet for a month or two; the two actual
thresholds do not depend on history.

This is deliberately **not** `platformMonthlyUsdCap`. That parameter is a
display-only LLM spend watch line the portal renders on the Activity page — a
different number measuring a different thing, and reading it here produced a
budget that sat _below_ expected spend whenever the firewall was on. The deploy
echoes both `costBudgetUsd` and `expectedMonthlyUsd` so the pair can be checked
after any deploy that flips the firewall.

**Enforced LLM ceiling (separate from this budget).** `llmPlatformDollarsPerDay`
(default `-1`) becomes `EDGE_LLM_PLATFORM_DOLLARS_PER_DAY` on the **edge only**
(not the dev gateway). When unset (`-1`), the effective value is
`max(one tenth of platformMonthlyUsdCap, 3 × llmDefaultDollarsPerDay)` — `150`
with the stock `1000` / `50` defaults; when `platformMonthlyUsdCap` is `0` the
monthly tenth is `100` before that floor. An explicit parameter value is kept
as set. Set `0` to switch the ceiling off (one-organization installs,
ADR-0028). The edge warns at boot (`platform_ceiling.below_app_default_multiple`)
when the ceiling is on and below `3 × llmDefaultDollarsPerDay`. Apply the
`platform_llm_spend_micro_usd` migration before deploying an edge image that
enforces it. `modules/alerts.bicep` includes a rule on
`helix.gateway.admission_denied` with `reason = platform_ceiling` (KQL unverified
in Azure).

### Verifying it, which you must do explicitly

`snet-apps` is deny-by-default outbound and the **absence** of an allow rule
_is_ the enforcement, so a missing FQDN drops every span with no error anywhere.
`*.monitoring.azure.com` does **not** cover App Insights ingestion —
`*.in.applicationinsights.azure.com` is a separate entry in `firewall.bicep`.

**This fails as silence.** A green deploy proves nothing. Drive a request
through a deployed app, then look for the trace in Application Insights →
Transaction search. If it is absent, check the collector's own logs first
(`az containerapp logs show -n <prefix>-otel-apps`) — the collector reports an
export failure even when the services cannot.

Same discipline as the Key Vault private-DNS gotcha below, and for the same
reason: the failure is invisible in every place you would naturally look.

## Operator steps NOT done by this template

- **Entra app registrations** — create the three registrations (or use the
  `infra/entra` Bicep) and fill the client id / audience / admin-role / edge
  certificate params. Full walkthrough + gotchas (v2 tokens, cert auth, App
  Roles): `docs/runbooks/entra-app-registration.md`.
- **Wildcard ACME cert issuance/renewal** — portal scheduled job (deferred).
- **Postgres runtime roles + the FIRST migration** — steps 4 and 6 above
  (data-plane, not IaC). Subsequent migrations are not an operator step:
  `deployApps=true` creates the `<namePrefix>-migrate` job, which applies them
  without anyone handling the admin password (step 4's "Every migration" note).
- **Front Door / bastion** for operator access to the internal portal.
- **Passwordless (Entra) Postgres auth** — a hardening follow-up, and **not** the
  config flip an earlier version of this list implied. The managed identities do
  exist, but none of their grants are Postgres, and the server is deployed with
  `activeDirectoryAuth` disabled and no Entra administrator (`postgres.bicep`
  supports neither today). Four things would have to change together:
  1. the server: enable Entra auth + set an administrator;
  2. **the role model**: `pgaadauth_create_principal` names the Postgres role
     after the Entra identity, so the runtime role would be
     `<namePrefix>-edge-id`, not `helix_edge` — and every GRANT in every
     migration, plus the env-literal RLS policy pinning `helix_dev` to
     `env='dev'`, references those four names;
  3. **the apps**: an Entra token _is_ the password and expires hourly, so the
     static `connectionString` in `apps/portal/src/db/client.ts` and
     `apps/edge/src/db/pool.ts` can't hold it (`pg.Pool` does accept a `password`
     function, so it is feasible — but it is a change in three planes);
  4. **ADR-0029's portability premise**: the apps read env vars only, no cloud
     SDK. Token acquisition puts `@azure/identity` in every plane's request path.

  Treat it as its own ADR, not a step inside another piece of work. Note also
  that it would not by itself stop a resource-group Contributor reading platform
  secrets — those are readable from the container app definitions regardless (see
  "Known deploy gotchas"), so the win is narrower than it first appears.

- **Audit-log shipping to immutable blob** — descoped 2026-09-17: the
  tamper-evidence demand it served traced to a Phase-1 PM brief engineering
  never ratified (ADR-0021 amendment). `gateway_calls` stays append-only by DB
  grant for every runtime role; ledger retention/erasure (GDPR) is tracked in
  `TODO.md`.

## Known deploy gotchas

Wrinkles hit during the first real end-to-end deploy. Check these
if a deploy misbehaves:

- **✅ FIXED — the Key Vault private DNS zone had the wrong NAME.** `privatedns.bicep`
  derived it from `environment().suffixes.keyvaultDns`, which returns the **public**
  suffix `.vault.azure.net` and so produced `privatelink.vault.azure.net`. A vault's
  public name actually CNAMEs to `<name>.privatelink.`**`vaultcore`**`.azure.net`, so
  that is the only zone a private endpoint resolves through. The zone the template
  created was one nothing ever queried.

  > An earlier version of this entry diagnosed this as "the A records failed to
  > auto-register" and told you to backfill them into `privatelink.vault.azure.net`.
  > That was wrong and made it worse — it put records in the unused zone, which looks
  > like a fix and changes nothing.

  **The failure is silent in every place you would look.** The private endpoint
  provisions fine, its `privateDnsZoneGroups` reports `Succeeded`, A records are
  present, and the zone is linked to the VNet. Only a data-plane call from inside the
  VNet reveals it — in-VNet DNS falls through to the vault's public IPs and Key Vault
  rejects the request:

  ```
  (Forbidden) Public network access is disabled and request is not from a trusted
  service nor via an approved private link.
  ```

  Diagnose it by resolving the vault from **inside** the VNet and checking whether you
  get the PE's private IP or a public one:

  ```bash
  getent hosts <kv-name>.vault.azure.net    # from a job/container in the apps env
  ```

  **This went unnoticed on both installs for a long time because nothing depended on
  it.** Platform secrets are direct-injected as env vars (ADR-0029), not read from the
  vault at runtime, so the apps never resolved it. The first component that genuinely
  needs it is the migration job (see step 4's "Every migration"). Note that
  **egress → `kv-connections` at runtime (ADR-0006) is affected too** — it will fail
  the same way as soon as a connection secret exists.

  Repairing an install deployed before the fix, without a full re-apply:

  ```bash
  ZONE=privatelink.vaultcore.azure.net
  az network private-dns zone create -g <rg> -n $ZONE
  az network private-dns link vnet create -g <rg> -z $ZONE -n link-to-vnet \
    --virtual-network <vnet> --registration-enabled false
  # repoint each vault PE at the correct zone; Azure then registers the A records
  for pe in <kv-connections>-pe <kv-platform>-pe; do
    az network private-endpoint dns-zone-group add -g <rg> --endpoint-name "$pe" \
      -n default --private-dns-zone $ZONE --zone-name vaultcore
    az network private-endpoint dns-zone-group remove -g <rg> --endpoint-name "$pe" \
      -n default --zone-name vault          # drop the stale config
  done
  # then delete the orphaned privatelink.vault.azure.net zone (and its vnet link) so it
  # cannot mislead the next person
  ```

- **How a rotated platform secret actually reaches the apps (verified
  2026-09-17).** The apps hold Key Vault _references_ now, and ACA secrets are
  app-level config, not revision template — so the three ways to poke the
  machinery behave very differently:
  - **Write the vault and walk away:** ACA's background refresh notices the new
    version and restarts revisions itself within ~30 min (observed: 22 min). No
    redeploy, no operator action — the normal rotation path.
  - **Force it now:** any app-config write re-resolves every reference at
    once — e.g. re-run the same `az containerapp secret set` for one of the
    app's refs. Use this after an emergency rotation.
  - **`az containerapp revision restart` does NOT re-resolve.** It bounces the
    replicas against the value snapshot stored with the revision. Verified: after
    a vault write + manual restart the app still served the _old_ value. Do not
    "verify" a rotation this way — check the resolved value instead:
    `az containerapp secret show -g <rg> -n <app> --secret-name <name>`.
  - Direct-value secrets (the otel collectors' App Insights connection string)
    are unchanged by all this: a value-only redeploy still does not roll a
    revision; force one with `az containerapp update -g <rg> -n <app>
--revision-suffix <tag>`.

- **Resource-group Contributor is effectively platform-secret read access.** The
  apps now hold Key Vault _references_ (see "Platform secret delivery"), but the
  `listSecrets` API resolves them: `az containerapp secret list -n <app>
--show-values` returns the **resolved values** for references too (verified
  2026-09-17). That is a control-plane call, so `kv-platform` being
  private-endpoint-only does not prevent it. Two consequences worth planning
  around:
  - **Scope deploy principals accordingly.** Anything holding Contributor on the
    resource group can read every per-role Postgres DSN, `EDGE_AUTH_SECRET`,
    `PORTAL_SECRET`, the internal seam keys (`HELIX_INSTRUCTION_SECRET`,
    `HELIX_INTERNAL_SECRET`, `HELIX_EXCHANGE_SECRET`), and the edge OIDC private key.
    Nothing delegated lands in `kv-platform` — that is what `kv-delegated` is for.
  - **It is also the recovery path.** Secrets generated at deploy time and never
    captured are _not_ lost — they can be read back from a running install (the
    same values are in `kv-platform`). When the dev surface is off the `helix_dev`
    DSN is absent, but it resets losslessly.
  - **The Postgres admin password is now in `kv-platform` too**, because the
    migrate job needs to read it (see step 4). It is still absent from every
    container, so `containerapp secret list` does not expose it — but a principal
    that can read the vault's data plane from inside the VNet can. That is a
    deliberate trade: it buys migrations that no human or pipeline has to hold a
    schema-owner credential for.

- **A template re-apply strips the TLS custom-domain bindings only while
  `wildcardTlsBound=false`.** With the gate on, the bindings are declared by the
  template (`customDomains` referencing the env-store cert — ADR-0044) and an apply
  preserves them; the canary in "Wildcard TLS" catches a wrongly-off flag at what-if
  time. While it is off — a fresh install before bootstrap, or an install that never
  flipped — the old semantics apply: the bindings are made by the job at runtime, but
  `containerapp.bicep`'s ingress omits `customDomains`, so any full
  `az deployment group create` strips every bound hostname and all custom domains
  immediately serve the ACA default cert (browsers fail TLS verification). **After
  such an apply, re-bind against the cert already in the environment store** — filter
  by the deterministic name, not by position (`[0]` picks whatever is first):

  ```bash
  CERT_ID=$(az containerapp env certificate list -g <rg> -n <env> \
    --query "[?name=='wildcard-<appsDomain-with-dashes>'].id" -o tsv)
  az containerapp hostname bind -g <rg> -n <app> \
    --hostname '<host>' --environment <env> --certificate "$CERT_ID"
  ```

  Do **not** reach for `az containerapp job start` as the recovery reflex: the job's
  issuance guard fails open when it cannot read the store, and inside the Let's
  Encrypt renewal window (`renewBeforeDays`, ~30 days before expiry) that spends one
  of the 5 duplicate certificates per 7 days. Triggering the job is the fresh-install
  bootstrap path, not the recovery path. The same applies to a gated apply that fails
  loudly on a missing cert: the recovery is to flip the gate back off (or restore the
  cert under its deterministic name), not to re-issue.

  A **scoped `az containerapp update`** (e.g. `--set-env-vars`) does _not_ wipe the
  bindings — only a full ARM apply reconciles the whole resource — so prefer that for
  single-knob changes to a live install.

  **The declared set is an allowlist.** A gated apply preserves exactly the bindings
  `main.bicep` declares (the edge wildcard, and `portal.` / `dev-api.` when those
  planes are external) and **deletes anything else** — a hostname bound by hand is
  silently removed by the next apply, with no self-heal (the job binds only its own
  three). A host that needs a binding gets a row in `main.bicep`, not an
  `az containerapp hostname bind`.

  This matters most for **automated re-applies**: a workflow that re-applies the
  template with the gate off silently breaks TLS on every release. With the gate on
  there is nothing to repair — but the apply is still dangerous for the reasons that
  remain (an absent secret renders as `''` over the live value), so this closes one
  hazard, not the case for running Bicep from CI.

- **Provider registration can wedge.** `Microsoft.DBforPostgreSQL` (and friends) can
  sit in `Registering` for a long time; re-issuing `az provider register -n <ns>`
  nudges it to `Registered`.

## Verifying the isolation (post-deploy)

> Assumes `deployFirewall=true` (the default). With the firewall **off**, the
> edge outbound check below **succeeds** instead of failing — the egress-only
> zone is not enforced (see "Optional: the egress firewall"). The private
> data-services checks hold regardless of the flag.

```bash
# the images carry no curl/wget, and exec needs a TTY — probe with node over a
# pseudo-TTY (script(1) supplies it)

# from an edge replica: outbound internet must FAIL, egress must succeed
script -q /dev/null az containerapp exec -g <rg> -n helix-prod-edge --command \
  "node -e \"fetch('https://example.com').then(r=>console.log(r.status)).catch(e=>console.log('ERR',e.cause?.code))\"" < /dev/null
# expect: ERR (blocked)

script -q /dev/null az containerapp exec -g <rg> -n helix-prod-edge --command \
  "node -e \"fetch(process.env.EDGE_EGRESS_URL+'/health').then(r=>console.log(r.status)).catch(e=>console.log('ERR',e.cause?.code))\"" < /dev/null
# expect: 200

# edge -> portal rides EDGE_PORTAL_URL — probe it before trusting the
# connections surfaces, the same way
script -q /dev/null az containerapp exec -g <rg> -n helix-prod-edge --command \
  "node -e \"fetch(process.env.EDGE_PORTAL_URL+'/health').then(r=>console.log(r.status)).catch(e=>console.log('ERR',e.cause?.code))\"" < /dev/null
# expect: 200

# from an egress replica: outbound internet must SUCCEED
script -q /dev/null az containerapp exec -g <rg> -n helix-prod-egress --command \
  "node -e \"fetch('https://example.com').then(r=>console.log(r.status)).catch(e=>console.log('ERR',e.cause?.code))\"" < /dev/null
# expect: 200

# data services are private — confirm publicNetworkAccess is Disabled
az postgres flexible-server show -g <rg> -n helix-prod-pg --query network
az keyvault show -n helix-prod-kvc --query properties.publicNetworkAccess
```
