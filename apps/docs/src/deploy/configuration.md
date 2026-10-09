---
title: Configuration reference
description: "Every operator knob in two places: Bicep parameters resolved server-side from the install's Key Vault, and per-service environment variables."
---

# Configuration reference

Everything an operator configures lives in two places:

- **Bicep parameters** — `infra/azure/main.bicepparam`, applied by the deploy.
  The secret parameters carry no values: each is an `az.getSecret()` line that
  resolves from the install's own platform Key Vault, server-side at ARM, at
  deploy time.
- **The platform Key Vault** — the source of truth for every platform secret.
  The container apps hold versionless Key Vault *references* to it (resolved by
  Container Apps from inside the environment's VNet — the vault stays
  private-endpoint-only), and the apps themselves read only plain env vars.
  Environment variables appear exactly once in the lifecycle: the fresh-install
  bootstrap, before the vault exists — see
  [Secret environment variables](#secret-environment-variables).

This page lists the parameters you will actually touch, grouped by what they
affect. Every parameter also carries a `@description` in
[`main.bicep`](https://github.com/AZX-PBC-OSS/helix/blob/main/infra/azure/main.bicep),
which is the complete and current list.

## Names and resources

| Parameter | Default | What it is |
| --- | --- | --- |
| `namePrefix` | `helix-prod` | Prefix for every resource name |
| `location` | resource group's region | Azure region for all resources |
| `storageAccountName` | — | Globally unique, 3–24 lowercase alphanumerics |
| `platformVaultName` | — | Globally unique Key Vault name (platform config secrets) |
| `connectionsVaultName` | — | Globally unique Key Vault name (app connection secrets) |
| `delegatedVaultName` | — | Globally unique Key Vault name (user-delegated OAuth token material, egress-only) |
| `postgresServerName` | — | Globally unique Postgres Flexible Server name |
| `blobContainerName` | `app-bundles` | Blob container for app bundles |

## Data

| Parameter | Default | What it is |
| --- | --- | --- |
| `postgresSkuName` | `Standard_D2ds_v5` | Postgres SKU. A `Standard_B1ms` burstable SKU is fine for small installs and costs meaningfully less |
| `postgresSkuTier` | `GeneralPurpose` | Must match the SKU family (`Burstable` for B-series) |
| `postgresStorageSizeGB` | `32` | Postgres disk size. Growing it is a maintenance operation |

The Postgres **major version is deliberately not a parameter** — the module
default is the only control, so pulling new template commits into an apply can
drive an in-place major-version upgrade. Compare the live server version
against the module default before applying; see [Deploying
updates](/deploy/updates#when-you-do-need-a-full-apply).

## Domains and TLS

| Parameter | Default | What it is |
| --- | --- | --- |
| `appsDomain` | — | Your apps domain. Apps live on `<slug>.<appsDomain>`, sign-in on `auth.<appsDomain>`, the portal on `portal.<appsDomain>` |
| `deployCertbot` | `true` | The scheduled job that issues and renews the `*.<appsDomain>` Let's Encrypt certificate via DNS-01 |
| `acmeEmail` | *(empty)* | Required for the certificate — the job is skipped without it |
| `acmeServer` | Let's Encrypt **staging** | Switch to `https://acme-v02.api.letsencrypt.org/directory` once the flow is validated |
| `wildcardTlsBound` | `false` | Flip to `true` after the first certbot run (see below) |
| `domainVerificationId` | *(empty)* | ACA's custom-domain verification id (from the edge deployment output), needed before the first certbot run |
| `edgeTrustProxy` | `auto` | The address of the ingress the edge should trust for `req.ip`. Leave at `auto` behind ACA; set an address only if something else fronts the edge |

## TLS: the `wildcardTlsBound` flag

A certificate has to exist before a hostname can bind to it, so this is a
two-phase flag. While it is `false` (a fresh install), the certbot job makes
the bindings at runtime — but a full template re-apply **strips** them. After
the first successful certbot run, set it to `true` and re-apply; from then on
the template declares the bindings itself and re-applies preserve them.

Set it literally in `main.bicepparam`, never from an environment variable — a
set-but-blank variable reads as `false`, and that is the direction that wipes
the bindings. The what-if check in
[getting started](/deploy/getting-started#step-3-deploy-the-infrastructure)
catches a wrongly-off flag before it does damage.

## Feature gates

| Parameter | Default | What it is |
| --- | --- | --- |
| `deployApps` | `false` | The two-phase switch: `false` deploys infrastructure only, `true` adds the container apps |
| `deployFirewall` | `true` | The Azure Firewall that enforces the egress-only network zone. **Keep on for production** — it is the primary outbound control. `false` saves ~$920/month and is for dev/test installs only |
| `deployDevGateway` | `false` | The opt-in cross-origin dev surface (`dev-api.<appsDomain>`) for building apps locally against a deployed platform |
| `portalExternal` | `false` | Puts the portal on the public load balancer at `portal.<appsDomain>`, gated by Entra sign-in. Without it (or a private network path), nobody can reach the portal |
| `allowPublicApps` | `false` | Permits `public` (anonymous) app visibility on this install |
| `allowPasswordApps` | `false` | Permits `password` (shared-passphrase) app visibility |
| `deployFoundry` | `false` | Deploys an Azure AI Foundry account with the `foundryModels` deployments and routes all LLM inference to it, keyless (managed identity — no vendor key). See [Azure AI Foundry](/deploy/foundry) |

## Azure AI Foundry

The full story — quota, regions, Marketplace terms, bring-your-own — is on
[Azure AI Foundry](/deploy/foundry). The parameters:

| Parameter | Default | What it is |
| --- | --- | --- |
| `deployFoundry` | `false` | Creates the account (in its own resource group) + deployments and wires both model families at it. Overrides the six `llm*` params |
| `foundryModels` | the catalog subset a fresh subscription can deploy | Models to deploy: `{ name, format, modelVersion?, modelName?, skuName?, capacity?, raiPolicyName? }`. Deployment `name` == the model id apps request; `modelName` is the escape hatch when the Foundry catalog's model name differs from it. Deployments are pay-per-token and cost nothing idle. The default excludes models a fresh pay-as-you-go subscription cannot deploy (Deprecating defaults, zero-quota Claude incl. `claude-sonnet-5`, unverified `gpt-4.1` family) — add them back once quota/verification lands |
| `egressManagedIdentityConnections` | *(empty)* | BYO-Foundry keyless: `connection=host-suffix` pairs egress may mint managed-identity tokens for. Ignored when `deployFoundry` is on |
| `foundryAttestation` | *(empty)* | Anthropic Marketplace attestation (`organizationName`/`countryCode`/`industry`) — required for Claude models on a fresh subscription |
| `foundryLocation` | the platform `location` | Account region. Model availability is regional; Claude is narrower than GPT |
| `foundryAccountName` | `<namePrefix>-foundry` | Globally unique (becomes `<name>.services.ai.azure.com`) |
| `foundryResourceGroupName` | `<namePrefix>-foundry-rg` | The account's own resource group — the boundary that keeps LLM spend out of the platform budget and gives it its own |
| `foundryDefaultCapacity` | `50` | Per-deployment rate limit in thousand-TPM units — a starting point; tiers scale with usage |
| `foundryDisableLocalAuth` | `true` | Refuses API-key auth on the account. Leave on: with managed identity there are no keys to leak |

The six `llm*` parameters (`llmEndpoint`, `llmAnthropicPath`,
`llmAnthropicConnection`, and the `llmOpenAi*` triple) are the BYO/manual path —
first-party defaults, or pointed at an existing Foundry account per the
[BYO section](/deploy/foundry#bring-your-own-foundry).

## App behavior

| Parameter | Default | What it is |
| --- | --- | --- |
| `llmEndpoint` / `llmOpenAiEndpoint` | `https://api.anthropic.com` / `https://api.openai.com` | The LLM upstreams the edge gateway proxies to (per model family). See [Azure AI Foundry](/deploy/foundry) for pointing them at your own subscription |
| `llmModelAllowlist` | *(empty)* | Catalog ids the portal advertises as servable (capability catalogue, agent skill, model picker). Empty with `deployFoundry` auto-derives from `foundryModels`; empty without it derives from seeded platform secrets. Set it to declare the set explicitly (e.g. a BYO Foundry serving a subset). Ids outside the platform catalog are ignored |
| `llmModelBlocklist` | *(empty)* | Catalog ids withheld even when otherwise servable, subtracted in either allowlist mode — the "everything except these" knob (e.g. `['claude-fable-5']` when your Anthropic upstream lacks that line) |
| `platformMonthlyUsdCap` | `1000` | Display-only LLM spend line on the admin Activity page. `0` hides it. The enforced daily LLM ceiling defaults to one tenth of this value (`llmPlatformDollarsPerDay`) |
| `llmDefaultDollarsPerDay` | `50` | Daily LLM spend enforced when an app's manifest omits `dollarsPerDay` (`EDGE_LLM_DEFAULT_DOLLARS_PER_DAY` on the edge and dev gateway). Matches the approval baseline; raising it enforces more than the classifier showed approvers. `0` = unset is unlimited |
| `llmPlatformDollarsPerDay` | `-1` | Platform-wide daily LLM ceiling enforced on the edge (`EDGE_LLM_PLATFORM_DOLLARS_PER_DAY`). `-1` derives one tenth of `platformMonthlyUsdCap` (or `100` when that is `0`). `0` switches enforcement off. Apply the `platform_llm_spend_micro_usd` migration before the edge image that reads it |
| `deployMaxFileMb` | `50` | Max uncompressed size of any single file in a deployed bundle |
| `deployMaxBundleMb` | `250` | Max uncompressed size of the whole bundle (and the compressed upload). Raising it a lot wants more CPU/memory on the portal container |
| `fetchMaxBodyMb` | `25` | Max size of each direction of a `/_api/fetch` call (the request body and the response body). Sets `EDGE_FETCH_MAX_BODY_BYTES` on the edge and dev gateway and `EGRESS_MAX_BODY_BYTES` on egress; each hop enforces it, and a call over it gets a 413 |
| `imageRegistry` / `imageTag` | `ghcr.io/azx-pbc-oss` / `latest` | Where the three service images come from |
| `logLevel` | `info` | Log level for all four services. `debug` on the edge puts app-request detail in Log Analytics (30-day retention) — treat it as a data decision, not a volume one |

## Observability and alerts

| Parameter | Default | What it is |
| --- | --- | --- |
| `deployTelemetry` | `true` | OTLP collectors + Application Insights. `false` leaves telemetry inert — the platform's documented default state |
| `deployAlerts` | `true` | Alert rules on the platform's own telemetry (registry staleness) |
| `deployAvailabilityTests` | `true` | Outside HTTP probes on the public hosts — the only monitoring that works when the platform can't see itself. Billed per execution |
| `deployInfraAlerts` | `true` | Azure platform-metric rules: Postgres availability/storage, restart storms, edge 5xx |
| `alertEmails` | `[]` | Who alerts notify. **Empty means the rules still deploy and still fire — at nobody.** Always set this, or turn alerts off |
| `registryStalenessThresholdMs` | `1200000` | Staleness that fires the registry alert |
| `availabilityTestFrequencySeconds` | `300` | Probe interval per location — the cost knob for availability tests |
| `availabilityExtraTargets` | `[]` | Extra URLs to probe, e.g. one real hosted app |
| `edgeServerErrorThreshold` | `100` | Edge 5xx per 15 minutes before the alert fires. Deliberately insensitive: one broken app is not a platform incident |

## Cost

| Parameter | Default | What it is |
| --- | --- | --- |
| `deployCostBudget` | `true` | A monthly budget that **notifies** — nothing enforces it |
| `expectedMonthlyUsdExFirewall` | `125` | Expected monthly spend without the firewall. **Set this per install** — the Postgres SKU alone moves it by 2× |
| `firewallMonthlyUsd` | `920` | What `deployFirewall` adds per month |
| `budgetHeadroomPercent` | `160` | Budget = expected × this. Below ~125% the notifications become a monthly "all is well" reminder |
| `monthlyCostBudgetUsd` | `0` | Override the derived budget entirely |
| `llmMonthlyBudgetUsd` | `1000` | LLM-axis budget on the Foundry account's own group (`deployFoundry` only). A direct amount, not derived; `0` = no LLM budget. Notify-only — per-app daily budgets and the deployments' TPM capacity are the real limits |

## Secret environment variables

These appear in exactly one place: the **fresh-install bootstrap**, before the
platform vault exists. `main.bootstrap.bicepparam` reads them from the
environment; the first applies write them into the vault, and from then on the
vault is the source of truth — steady-state applies source them with
`az.getSecret()` and read nothing secret from the environment. Keep the
generated values in your secrets store for disaster recovery, but expect to
never export them again.

| Variable | What |
| --- | --- |
| `HELIX_PG_ADMIN_PASSWORD` | Postgres admin password |
| `HELIX_EDGE_DB_PASSWORD` / `HELIX_PORTAL_DB_PASSWORD` / `HELIX_EGRESS_DB_PASSWORD` / `HELIX_DEV_DB_PASSWORD` | Per-role database passwords (each container runs as its own least-privilege Postgres role). Steady state sources the *assembled DSNs* instead (`edge-database-url` &c. in the vault); these are the bootstrap-only building blocks |
| `HELIX_EDGE_AUTH_SECRET` | Session cookie signing root |
| `HELIX_PORTAL_SECRET` | Shared-password app encryption key |
| `HELIX_INSTRUCTION_SECRET` | Shared edge→egress attestation key |
| `HELIX_INTERNAL_SECRET` | Shared edge↔portal internal-JWT key (the edge mints, the portal verifies) |
| `HELIX_EXCHANGE_SECRET` | Shared portal↔egress internal-JWT key (the portal mints, egress verifies) |
| `HELIX_EDGE_OIDC_PRIVATE_KEY` / `HELIX_EDGE_OIDC_CERTIFICATE` | Edge OIDC client certificate (base64 PEMs) |
| `HELIX_EDGE_OIDC_CLIENT_ID`, `HELIX_PORTAL_OIDC_AUDIENCE`, `HELIX_PORTAL_ADMIN_GROUP_ID`, `HELIX_AZX_CLI_CLIENT_ID`, `HELIX_AZX_WEB_CLIENT_ID` | The Entra values from [Entra setup](/deploy/entra-setup) — not secret, but env-sourced the same way |

Encoding rules live with the generation commands in
[Getting started](/deploy/getting-started#step-3-deploy-the-infrastructure)
(DSN passwords base64url; signing secrets standard base64).

Rotating any of these afterwards starts at the vault, not the environment —
see [Rotating a secret](/deploy/updates#rotating-a-secret).

## Runtime environment variables

Most runtime configuration is template-computed, not operator-set. The three
worth knowing are the ones the portal SPA reads at runtime (the SPA has no
build-time configuration at all):

| Variable | Set from | If absent |
| --- | --- | --- |
| `APP_PUBLIC_BASE` | `https://<appsDomain>` | The portal refuses to boot |
| `DEV_API_PUBLIC_BASE` | set when `deployDevGateway` | The SPA reports dev mode as disabled |
| `PLATFORM_MONTHLY_USD_CAP` | `platformMonthlyUsdCap` | No spend line on the Activity page |
| `EDGE_LLM_DEFAULT_DOLLARS_PER_DAY` | `llmDefaultDollarsPerDay` | Apps with no manifest `dollarsPerDay` use the install default ($50/day unless raised); `0` on the parameter means unset is unlimited |
| `EDGE_LLM_PLATFORM_DOLLARS_PER_DAY` | `llmPlatformDollarsPerDay` | Edge-only enforced platform daily LLM ceiling in USD; `0` disables. Not set on the dev gateway |

The OAuth connections feature adds three more template-derived URLs —
each is the target app's ingress FQDN, so there is nothing to configure:

| Variable | App(s) | Set from | If absent |
| --- | --- | --- | --- |
| `EDGE_PORTAL_URL` | edge, dev-gateway | the portal's ingress FQDN | `/connections/*` proxy and consent surfaces answer fail-closed 503 |
| `PORTAL_EGRESS_URL` | portal | egress's ingress FQDN | the OAuth callback's code-exchange delegation is unwired; completion refuses |
| `AZURE_DELEGATED_KEY_VAULT_URL` | egress | the `kv-delegated` vault URI | no delegated store is built; delegated-token operations fail closed |

The fetch-proxy body cap is set on every hop that enforces it, from one
parameter:

| Variable | App(s) | Set from | If absent |
| --- | --- | --- | --- |
| `EDGE_FETCH_MAX_BODY_BYTES` | edge, dev-gateway | `fetchMaxBodyMb` × 1 MiB | 10 MiB |
| `EGRESS_MAX_BODY_BYTES` | egress | `fetchMaxBodyMb` × 1 MiB | 10 MiB |

The portal image also carries one setting for the app owner's Visitors view:

| Variable | Set from | If absent |
| --- | --- | --- |
| `PORTAL_GEOIP_DB_PATH` | the portal image (a DB-IP City Lite file downloaded at build) | Visit counts still work; approximate location reports itself unavailable |

The geolocation file is baked in when the portal image is built, so a new
monthly release arrives with the next image. If the download fails, the build
warns and continues, and the image ships without location. Pin a release with
the `GEOIP_DB_MONTH=YYYY-MM` build argument (a pinned release that can't be
downloaded fails the build), or pass `GEOIP_DB_MONTH=skip` to build without
one. DB-IP Lite is licensed CC-BY 4.0. The portal shows the required
attribution beside the location table; keep it if you change the UI. No visitor
address is sent anywhere, because the lookup reads the local file.

Per-service variables (OIDC endpoints, feature flags, database URLs) are read
in each service's `config.ts`: [`apps/edge/src/config.ts`](https://github.com/AZX-PBC-OSS/helix/blob/main/apps/edge/src/config.ts),
[`apps/portal/src/config.ts`](https://github.com/AZX-PBC-OSS/helix/blob/main/apps/portal/src/config.ts),
[`apps/egress/src/config.ts`](https://github.com/AZX-PBC-OSS/helix/blob/main/apps/egress/src/config.ts).
