---
title: Getting started
description: "The full first deployment on Azure, start to finish: infrastructure, database, the three services, and TLS, from one Bicep template."
---

# Deploy Helix on Azure

This page walks through a full deployment: infrastructure, database, the three
services, and TLS. The whole thing is one Bicep template in
[`infra/azure`](https://github.com/AZX-PBC-OSS/helix/tree/main/infra/azure).
That directory's [README](https://github.com/AZX-PBC-OSS/helix/blob/main/infra/azure/README.md)
is the complete operational reference, including known deploy gotchas; this
page is the shorter path through it.

## What gets deployed

| Layer | Resources |
| --- | --- |
| Network | VNet, subnets, optional Azure Firewall, private DNS zones |
| Data | Postgres Flexible Server (private), Blob storage (private) |
| Secrets | Two Key Vaults — platform config, and app connection secrets (both private) |
| Compute | Two Container Apps environments, running the edge, portal, and egress services |
| DNS | A public DNS zone for your apps domain |
| Observability | Application Insights, OTLP collectors, alert rules, an outside uptime probe |

The three services are published to GitHub's container registry by CI, so a
normal deploy builds nothing locally — you pick a published image tag.

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
            private endpoints → Postgres · Blob · KV×2
```

- The **edge** can be reached from the internet but cannot reach it — its
  subnet's default route goes to the firewall, which denies.
- **Egress** is the only subnet the firewall lets out, and it has no public
  ingress. It is the only component that ever holds an app connection secret.
- All data services are private-endpoint only; `publicNetworkAccess` is off.
- The **edge identity has no role on the connections vault** — an edge RCE
  cannot read a single app secret.

## What it costs

The default shape costs roughly **$125/month**. The one expensive optional is
the Azure Firewall: about **$920/month**, flat whether busy or idle. **Baseline
egress control on every install** is the application SSRF filter plus the
`snet-egress` NSG. The firewall adds FQDN allow-listing and threat intelligence
when `deployFirewall=true`; it is on by default in the template.

- Production, or anything hosting apps from multiple authors: keep the firewall.
  Use `egressFqdnMode=allowlist` on new installs; existing firewall installs
  stay on `any` until you flip explicitly (operator cost: maintain
  `egressAllowedFqdns` — see [network controls](/deploy/configuration#feature-gates)).
- A dev or test install: `deployFirewall=false` saves the money. Data services
  stay private either way; the NSG and application filter still apply.

A monthly budget alert is deployed alongside, sized from these two numbers, so
tune `expectedMonthlyUsdExFirewall` if your Postgres SKU differs much from the
default. See the [configuration reference](/deploy/configuration#cost).

## Prerequisites

- An Azure subscription and a resource group, with the `az` CLI logged in.
  On a fresh subscription, register the resource providers first — the deploy
  fails on an unregistered namespace, and a registration can sit in
  `Registering` for a long time (re-issue the command to nudge it):

  ```bash
  for ns in Microsoft.App Microsoft.Storage Microsoft.OperationalInsights \
            Microsoft.DBforPostgreSQL; do
    az provider register -n "$ns"
  done
  # add Microsoft.CognitiveServices if you plan to use deployFoundry
  ```

- A region picked **with Postgres availability checked for that
  subscription** — restrictions are per subscription, not per region, so a
  region one subscription can use may be refused for another:

  ```bash
  az postgres flexible-server list-skus -l <region>
  # a `reason` field on the first element means restricted — pick another region
  ```

- Compute quota for **two Container Apps environments** in that region — the
  deploy creates one for apps and one for egress, and a fresh or trial
  subscription can default below that, which fails the second environment
  mid-apply:

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

  Short? Portal → **Quotas** → provider *Azure Container Apps* → *Managed
  Environment Count*. Region-scoped increases are integrated requests —
  usually approved in minutes, but they can take days, so check before you
  need it.

- A Microsoft Entra tenant you can create app registrations in.
- A DNS domain you control, to delegate as the apps domain (e.g.
  `apps.example.com`). Apps live on `<slug>.<appsDomain>`, the portal on
  `portal.<appsDomain>`, and sign-in happens on `auth.<appsDomain>`. Every app
  gets its own origin — deliberate isolation, since every hosted app is
  untrusted code: the browser's same-origin policy is what keeps one app's
  code away from another app's data, and the platform manages it all.
- `openssl` and `python3` on the machine you deploy from (the database
  bootstrap script uses both). Everything else runs inside Azure.

## Step 1: Entra app registrations

Helix needs three app registrations in your tenant (edge, portal, CLI), plus
client ids and — for the edge — a certificate. It is a half hour of portal
clicks and it is fully documented: **[Entra ID setup](/deploy/entra-setup)**.

This is also when to decide who gets in. By default a fresh install is open
to every member of your tenant; the recommended shape is one Entra security
group per audience — app users, portal users, platform admins — with sign-in
restricted to them. See **[Access control](/deploy/access-control)**.

Do this first; the values feed the deploy in the next step.

## Step 2: Fill in the parameters

The template ships **two** params files, because of one hard rule worth
understanding up front: `az.getSecret()` — the mechanism that lets a deploy
read secrets straight from your own Key Vault, resolved server-side by ARM —
cannot be combined with any fallback expression (it is a compile error,
BCP351, anywhere but a direct parameter assignment). So the env-var path and
the vault path are two files, not one clever one:

- **`infra/azure/main.bootstrap.bicepparam`** — secrets are read from
  environment variables. This is the fresh-install file: you use it until the
  platform vault exists and is seeded (the first two applies below).
- **`infra/azure/main.bicepparam`** — the steady-state file. Every secret is
  an `az.getSecret()` line pointing at your vault; no secret ever touches your
  shell again. You switch to it after step 5.

Copy `main.bootstrap.bicepparam` and set, at minimum:

- Names: `namePrefix`, `storageAccountName`, `platformVaultName`,
  `connectionsVaultName`, `postgresServerName` (vault and storage names are
  globally unique).
- `appsDomain` — your apps domain.
- The Entra ids from step 1: `edgeOidcClientId`, `portalOidcAudience` (the
  bare client-id GUID), `portalAdminGroupId` (`platform-admin`),
  `azxCliClientId`, `azxWebClientId`. (The edge OIDC **certificate pair** is a
  secret — it is part of step 3's exports, not this file.)
- `acmeEmail` — required for the wildcard certificate.
- `portalExternal: true` — unless you plan to reach the portal over a private
  network path, nothing is deployable without it. The portal is
  internal-by-default; this flag puts it on the public load balancer, gated by
  Entra sign-in.

The [configuration reference](/deploy/configuration) lists every parameter and
what it does.

## Step 3: Deploy the infrastructure

On a fresh install the vault does not exist yet, so the bootstrap file reads
the secrets from environment variables. Generate them, then deploy with apps
disabled — this pass creates the network, data services, vaults, and
identities, but no containers.

How the secrets will flow, so the rest of the install makes sense: **every
apply writes the generated values into the platform vault** (ARM
management-plane writes, so the vault's disabled public access is no
obstacle), and the container apps' secret entries are **Key Vault references**
into it, which Container Apps resolves from inside the environment's VNet —
the vault stays private-endpoint-only throughout. After seeding, the vault is
the source of truth: both the apps (references) and later deploys
(`az.getSecret()`) read from it, and the env vars below are never needed
again.

```bash
cd infra/azure

# Database passwords are interpolated into DSN URLs, so they must be
# base64URL — a plain base64 value containing / + = corrupts the DSN.
export HELIX_PG_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')
export HELIX_EDGE_DB_PASSWORD=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')
export HELIX_PORTAL_DB_PASSWORD=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')
export HELIX_EGRESS_DB_PASSWORD=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')
export HELIX_DEV_DB_PASSWORD=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')
# Signing secrets are base64-DECODED by the apps — standard base64 here.
# A base64url value makes the edge crash on boot.
export HELIX_EDGE_AUTH_SECRET=$(openssl rand -base64 48)
export HELIX_PORTAL_SECRET=$(openssl rand -base64 48)
export HELIX_INSTRUCTION_SECRET=$(openssl rand -base64 48)
export HELIX_EDGE_OIDC_PRIVATE_KEY=$(base64 -w0 edge-key.pem)
export HELIX_EDGE_OIDC_CERTIFICATE=$(base64 -w0 edge-cert.pem)
export HELIX_EDGE_OIDC_CLIENT_ID=<helix-edge client id>
export HELIX_PORTAL_OIDC_AUDIENCE=<helix-portal client id>
export HELIX_PORTAL_ADMIN_GROUP_ID=platform-admin
export HELIX_AZX_CLI_CLIENT_ID=<azx-cli client id>
export HELIX_AZX_WEB_CLIENT_ID=<helix-portal client id>

az deployment group create -g <rg> -f main.bicep -p main.bootstrap.bicepparam
```

Capture every generated value somewhere durable as you go. A lost value is
recoverable from a *running* install —
`az containerapp secret list -n <app> --show-values` reads the secrets back
over the control plane (the API resolves the Key Vault references), and the
Postgres admin password is also in the platform vault as
`postgres-admin-password` — but recovery needs a healthy install, so capture
stays the primary path. (The one value held in no container is
`HELIX_DEV_DB_PASSWORD` on an install with the dev surface off: set a fresh
one with `ALTER ROLE helix_dev` rather than hunting the original.)

::: tip Preview first
`az deployment group what-if -g <rg> -f main.bicep -p main.bootstrap.bicepparam`
shows what the apply will change. On any re-apply of an install with TLS
already bound, the what-if must **not** show a delete of
`properties.configuration.ingress.customDomains` — if it does, stop and see the
`wildcardTlsBound` note in the [configuration reference](/deploy/configuration#tls).
:::

## Step 4: Create the database roles

The deploy created the Postgres server and the `helix` database, but not the
four least-privilege runtime roles the services connect as (`helix_portal`,
`helix_edge`, `helix_egress`, `helix_dev`). Those come from the committed
`infra/azure/sql/01-roles.sql`, run once as the admin — and they must exist
before the first migration, because the migrations' table grants only apply to
roles that already exist.

Postgres is private-endpoint-only, so this runs as a throwaway Container Apps
job inside the VNet. A script in the repo wraps the whole operation — build the
job, run the SQL in it, poll the result, and delete the job afterwards:

```bash
RG=<rg> PREFIX=<namePrefix> infra/azure/scripts/create-roles.sh
```

It reads the same `HELIX_*` variables you exported in step 3 — set all five,
including `HELIX_DEV_DB_PASSWORD`. The `helix_dev` role is created even when
the dev gateway stays off: the extra role is harmless without its app, and
adding it later means re-running migrations to pick up its grants.

The job deletes itself when the script finishes — it carries the admin password
as a job secret, so it must not be left lying around (if the cleanup itself
fails, the script prints the one-line delete command). This is the only step in
the whole install where the admin password is placed on a resource. Every
migration after it — including the first one, in step 6 — runs through a job
that reads the password from Key Vault itself. [Database &
migrations](/deploy/database) explains the model.

## Step 5: Deploy the apps

Still the bootstrap file — this is the pass that seeds the vault with the apps
live to consume it:

```bash
export HELIX_IMAGE_TAG=<tag>
az deployment group create -g <rg> -f main.bicep -p main.bootstrap.bicepparam \
  --parameters deployApps=true
```

Images come from `ghcr.io/azx-pbc-oss` (edge, portal, egress). CI publishes
them on every push to the main branch and on `v*` tags. The three GHCR packages
must be **public** for the default anonymous pull to work — the repo being
public does not make its packages public; flip each one under
*Package settings → Change visibility*. To keep them private instead, pass a
`registries` credential to the container apps (see the infra README).

This pass also creates the `<namePrefix>-migrate` job used next. The apps boot
before the schema exists: they answer `/health` but fail real requests until
step 6 lands. That is expected on a fresh install — nothing has been delegated
in DNS yet, so nothing external can reach them.

**This was the last apply that needs the secret exports.** The vault now holds
every secret, so set up the steady-state file before the next apply: copy
`main.bicepparam`, set the same non-secret values, and replace the placeholder
subscription id / resource group / vault name in the `az.getSecret()` lines
with your own (they are literals by design — and keep every line: a parameter
left unset falls back to composing a database DSN from an *empty* password,
which the apply would then write into the vault). On a `deployDevGateway=true`
install, also uncomment the `edgeDevDatabaseUrl` line — that secret exists only
where the dev surface deploys. The vault was created with
`enabledForTemplateDeployment`, and your deploy principal needs
`Microsoft.KeyVault/vaults/deploy/action` (Owner/Contributor include it) —
nothing else has to change hands.

## Step 6: Run the first migration

The `<namePrefix>-migrate` job runs the portal image inside the VNet and reads
the Postgres admin password from Key Vault with its own managed identity — no
credential passes through your shell. Pin it to the tag being deployed, start
it, and then read the result:

```bash
az containerapp job update -g <rg> -n <namePrefix>-migrate \
  --image ghcr.io/azx-pbc-oss/helix-portal:<tag>
az containerapp job start  -g <rg> -n <namePrefix>-migrate

# a job that starts is not a job that succeeded — check the execution
az containerapp job execution list -g <rg> -n <namePrefix>-migrate \
  --query "[0].{name:name,status:properties.status,start:properties.startTime}"
```

Expect `Succeeded`. On `Failed`, the Prisma output in the job's logs is the
explanation — see [reading the migrate job's
output](/deploy/database#reading-the-migrate-jobs-output). Once it succeeds,
every app that was waiting on the schema comes up on its own.

Migrations are forward-only and run before the apps on every later update too —
that routine is in [Deploying updates](/deploy/updates).

## Step 7: DNS and TLS

1. **Delegate the domain.** In the parent zone, add NS records for
   `<appsDomain>` pointing at the nameservers in the deployment output
   `dnsNameServers`.
2. **Bootstrap the wildcard certificate.** A scheduled job (`certbot`) issues
   and renews `*.<appsDomain>` via Let's Encrypt DNS-01 and binds it. It needs
   the domain verified first: take the `customDomainVerificationId` from the
   edge deployment output, set it as the `domainVerificationId` parameter, and
   re-apply. Then run the job once:

   ```bash
   az containerapp job start -g <rg> -n <namePrefix>-certbot
   ```

   The delegation above must be live before this run — Let's Encrypt has to
   resolve the challenge TXT publicly.
3. **Flip `wildcardTlsBound: true`** in the params file and re-apply. From then
   on the template itself declares the certificate bindings, so re-applies
   preserve them. Set this literally in the file, never through an environment
   variable — a blank variable reads as false, and false is the direction that
   silently strips bindings.

The certificate defaults to the Let's Encrypt **staging** directory so you can
validate the flow without burning rate limits. Once it works, set `acmeServer`
to `https://acme-v02.api.letsencrypt.org/directory` and re-run the job.

## Step 8: Verify

- Sign in to `https://portal.<appsDomain>` with an admin-assigned user and
  check the admin pages appear.
- Deploy a test app (`helix create` + `helix deploy`, see
  [the CLI page](/apps/cli)) and open its URL — you should get the Entra
  sign-in redirect, then your app.
- Read the `alertsNotify` deployment output. It says whether your alert rules
  have anyone to notify; an empty `alertEmails` still deploys rules that fire
  into nothing.
- After enabling anything that changes egress, drive a request through a
  deployed app and check the trace lands in Application Insights. A missing
  allowlist rule fails as silence, not as an error.

## Next: shipping changes

From here on, an update is a scoped `az containerapp update` against a new
image tag, with the migrate job run first — not a re-apply of this template.
**[Deploying updates](/deploy/updates)** covers the routine release, what a
Container Apps rollout actually does (including why a failed one is silent),
rollback, secret rotation, and the hazards of the rarer full apply.
