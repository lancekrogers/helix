---
title: Deploying updates
description: "Every deploy after the first: shipping a new build, running migrations, rotating secrets, and when a change needs the whole template re-applied."
---

# Deploying updates

[Getting started](/deploy/getting-started) covers the first deploy. This page
covers every one after it: shipping a new build, running migrations, rotating
a secret, and the rarer case where a change needs the whole template
re-applied.

## Two ways to change a running install

Almost every update is the first kind. Use the second only when the change is
something no scoped command can express.

| | Scoped update | Full template apply |
| --- | --- | --- |
| Command | `az containerapp update` / `job update` | `az deployment group create` |
| Touches | Only what you name | Every resource in the template |
| Needs | Resource-group Contributor | Owner / User Access Administrator |
| Preserves | Env vars, secrets, TLS bindings | Only what the params file re-declares |
| Use for | New image tag, one env var, a restart | Topology, params, roles, new resources |

**Prefer the scoped update.** It touches only what you name, and it *converges*
toward the template, so the next full apply is a no-op on it. (The historical
reason was sharper — a full apply used to render an absent secret env var as
`''` over the live value. That hazard is gone: secrets now resolve from the
platform vault server-side, so an apply needs no secret on hand at all. The
blast-radius argument stands on its own.)

::: warning Don't run the platform Bicep from CI
A release pipeline should hold resource-group Contributor and roll image tags.
Keep the full apply a rare, high-privilege operation run by hand — see
[when you need one](#when-you-do-need-a-full-apply).
:::

## What CI publishes

Every push to the default branch and every `v*` tag builds four images and
pushes them to `ghcr.io/<owner>`:

| Image | Runs as |
| --- | --- |
| `helix-edge` | `<namePrefix>-edge`, and `<namePrefix>-dev-gateway` (same image, different command) |
| `helix-portal` | `<namePrefix>-portal`, and the `<namePrefix>-migrate` job |
| `helix-egress` | `<namePrefix>-egress` |
| `helix-certbot` | `<namePrefix>-certbot` job |

Each build is tagged four ways: `sha-<short>`, the branch name, `latest` (on
the default branch), and the semver for a `v*` tag.

**Deploy the immutable `sha-` tag, not `latest`.** A floating tag makes "what
is running" unanswerable, and that is the first question in an incident.
Resolve it once and reuse it:

```bash
TAG=$(crane ls ghcr.io/<owner>/helix-edge | grep '^sha-' | tail -1)
# or, from the repo:
TAG=sha-$(git rev-parse --short=7 HEAD)
```

Before rolling, confirm all four tags exist — a partially-published build is
the normal result of a CI run that failed in the `images` matrix:

```bash
for img in edge portal egress certbot; do
  docker manifest inspect "ghcr.io/<owner>/helix-$img:$TAG" >/dev/null \
    && echo "ok   $img" || echo "MISSING $img"
done
```

## If you build a release pipeline

The shape that works, and why:

- **Hold resource-group Contributor, nothing more.** Rolling image tags,
  updating and starting the migrate job, and tagging the resource group need
  no `Microsoft.Authorization/*` permission. A full template apply does — it
  creates role assignments — which is one of the reasons CI never runs one.
- **Know what Contributor implies.** The apps hold Key Vault *references* to
  the platform secrets, but the `listSecrets` API resolves them:
  `az containerapp secret list --show-values` returns the resolved values over
  the control plane, private vault notwithstanding. The
  pipeline's credential scope is therefore the real access boundary. With
  GitHub OIDC that boundary is the federated credential's subject — scope it
  to a GitHub Environment, and required reviewers on that Environment become a
  gate Azure enforces by refusing the token, not a convention.
- **Take the OIDC subject verbatim from GitHub.** GitHub emits ID-based
  subjects — `repo:<org>@<org-id>/<repo>@<repo-id>:environment:<name>` — so a
  renamed org or repo cannot silently transfer trust, and the classic
  `repo:<org>/<repo>` form no longer matches. A login failing with
  `AADSTS700213` prints the presented subject; compare it byte-for-byte with
  the federated credential's. Do not register the classic form as a fallback —
  rename-proofing is the point.
- **Migrate first, then roll.** The migrate step doubles as a canary: it runs
  the portal image at the new tag, so an image that cannot boot fails before
  any app is touched.
- **Report health, don't gate on it.** [What a rollout actually
  does](#what-a-rollout-actually-does) — Container Apps already prevents the
  outage, and failing the workflow neither rolls back nor holds traffic. The
  custom-domain binding check is the one worth blocking on: one API call per
  app, and losing a binding is an immediate TLS failure.

## The routine update

Migrate first, then roll the apps. Both steps are scoped commands.

### 1. Run migrations

Migrations run through the `<namePrefix>-migrate` job, which reads the Postgres
admin password from Key Vault with its own managed identity. Nobody handles
that password after the install's roles bootstrap. How the job works, and what
to do when it fails, is in [Database & migrations](/deploy/database).

```bash
az containerapp job update -g <rg> -n <namePrefix>-migrate \
  --image ghcr.io/<owner>/helix-portal:$TAG
az containerapp job start  -g <rg> -n <namePrefix>-migrate

# then read the result — a job that starts is not a job that succeeded
az containerapp job execution list -g <rg> -n <namePrefix>-migrate \
  --query "[0].{name:name,status:properties.status,start:properties.startTime}"
```

**Run it before the apps, on every update, even when you expect nothing
pending.** Migrations are forward-only, and a new image can carry code that
requires one — rolling the apps first works until the first release that does.

Two things that look like reasons to skip it, and are not:

- **`/health` returning 200 does not prove the schema is current.** The edge
  opens its database pool lazily, so a missing column surfaces at query time —
  under a real user, not at boot.
- **Running it when nothing is pending is free.** `prisma migrate deploy` is a
  no-op with nothing to apply, so it doubles as a cheap proof that the
  credential path still works.

### 2. Roll the apps

If this release tightens `img-src`, read [Upgrading to the tightened image policy](#upgrading-to-the-tightened-image-policy) step 0 first — set `imgSrcReportOnly = true` in your parameter file before rolling the edge image. If it ships hosted-app containment, read [Upgrading to hosted-app containment](#upgrading-to-hosted-app-containment) step 0 before rolling the edge image or running any full apply.

```bash
for app in edge portal egress; do
  az containerapp update -g <rg> -n "<namePrefix>-$app" \
    --image "ghcr.io/<owner>/helix-$app:$TAG"
done

# if the dev gateway is deployed — it runs the edge image
az containerapp update -g <rg> -n <namePrefix>-dev-gateway \
  --image "ghcr.io/<owner>/helix-edge:$TAG"
```

The certbot job is rolled the same way, with `job update`. It is a scheduled
job, so a new image takes effect at its next run.

### 3. Confirm the new code is actually live

Do not skip this step: a failed rollout is silent on this platform (the next
section explains why), and this check is what catches it.

```bash
az containerapp revision list -g <rg> -n <namePrefix>-edge \
  --query "[?properties.active].{rev:name,image:properties.template.containers[0].image,\
state:properties.runningState,replicas:properties.replicas}" -o table
```

The active revision's image must be the tag you just deployed, and its running
state must be `Running`. Two active revisions means the new one has not become
ready and the old one is still serving.

## Upgrading to the LLM spend controls

These notes are for an operator adopting the admission and metering work in a live install. Nothing
here runs automatically — you choose the order and the parameter values.

1. **Role bootstrap.** Apply `infra/azure/sql/01-roles.sql` as the database admin so `helix_edge`,
   `helix_egress`, and the other platform roles exist. The spend-control migrations grant privileges
   to `helix_edge` only when that role is present; if the roles are missing, those `GRANT` blocks are
   skipped silently and the edge will refuse to start once lease caps or the platform ceiling are on.

2. **Apply the migrations before any new edge image.** Run `pnpm --filter @azx-pbc/portal db:deploy`
   (or your usual migration path) so `platform_llm_spend_micro_usd` and `inflight_leases` exist. An
   edge that starts without them fails closed on its first ceiling or lease call. Confirm the
   migration identity's role name (`helixadmin` by default, the `postgresAdminLogin` parameter) is
   the role the owner policy on `gateway_calls` was created for.

3. **Egress and edge images.** Build and deploy the new egress and edge images. If the edge image
   ships tightened `img-src`, follow [Upgrading to the tightened image policy](#upgrading-to-the-tightened-image-policy) step 0 in your parameter file before rolling the edge. There is no extra data
   migration for the upstream abort or the charging change. New `error` rows carry `;usage=` markers;
   historical rows keep their $0. The new edge image enforces in-flight lease caps from **code
   defaults** (10 concurrent LLM calls per app, 3 per authenticated user) before you apply the Bicep
   template in step 6, so step 2 is not optional.

4. **List approved apps with no budget.** Before the install default takes effect, find apps that are
   unlimited today:

```sql
SELECT slug FROM apps
 WHERE capabilities->'llm' IS NOT NULL
   AND capabilities->'llm'->>'dollarsPerDay' IS NULL
   AND jsonb_array_length(COALESCE(capabilities->'llm'->'models', '[]'::jsonb)) > 0;
```

   These become $50 per day when the default deploys unless you change
   `llmDefaultDollarsPerDay`. Set an explicit number for each through the portal, or deploy with
   `llmDefaultDollarsPerDay` raised for a transition and lower it afterwards. Skipping this step
   means refusals on the first busy day. Column and JSON paths match `apps/portal/prisma/schema.prisma`
   (`App.capabilities`) and `packages/shared/src/approval.ts`; validate the query on your database
   before you rely on it in production.

5. **Choose the platform ceiling.** The Bicep default is one tenth of `platformMonthlyUsdCap` per
   day. Set it from the install's own ledger history; an untuned value either blocks real use or
   never trips. A one-organization install may set `llmPlatformDollarsPerDay` to `0` to switch the
   ceiling off and should record that choice in its own runbook.

6. **Apply the new template.** A Bicep default does not reach an install until you apply the template
   with your parameters. Set the four concurrency parameters (`llmMaxAppInFlight`,
   `llmMaxUserInFlight`, `llmMaxInFlight`, `fetchMaxAppInFlight`), the call deadline
   (`llmMaxCallMs`), and `llmDefaultDollarsPerDay` / `llmPlatformDollarsPerDay` there. See
   [Configuration](/deploy/configuration). If this template also ships network controls, read
   [Upgrading to the network controls](#upgrading-to-the-network-controls) step 0 first — set
   `egressNsgEnforce = 'off'` until the scratch-copy test passes before any full apply, including
   this step. If the template also ships tightened `img-src`, set `imgSrcReportOnly = true` in the
   parameter file first ([image policy step 0](#upgrading-to-the-tightened-image-policy)). If it also
   ships the apps/control domain split, read [Upgrading to hosted-app
   containment](#upgrading-to-hosted-app-containment) before changing `hostedAppsDomain`.

7. **Mixed replicas.** An edge revision without `EDGE_LLM_PLATFORM_DOLLARS_PER_DAY` disables the
   platform ceiling on that replica, so a rolling deploy with old and new replicas does not refuse
   calls for the ceiling until every replica carries the setting.

**Dev gateway.** Enabling `deployDevGateway` runs a separate edge process whose LLM traffic is tagged
`env=dev`. The platform daily ceiling sums only `env=prod`, so **dev-gateway LLM spend is outside
the platform ceiling** unless you accept that gap as a precondition or add your own controls. Per-app
budgets remain per env.

**Rollback.** Roll images back with `az containerapp update` as in step 2 above. Each Part 3 control
has an off value (`0`) except the call deadline. Migrations are additive and can stay.

**What was not verified in Azure.** Bicep parameters and edge/dev-gateway environment wiring
(compile-checked only); the platform-spend alert rule's query and whether it fires; the production
owner role under `FORCE` RLS; abort propagation through the Container Apps ingress between edge and
egress; lease behavior across real replicas.

## Upgrading to the network controls

These notes mirror the operator rollout in `docs/features/network-controls.md` in the
repository. Nothing here runs automatically.

0. **Hold the NSG off until the scratch copy passes.** Until you have attached the egress NSG on a
   non-production copy of the install and run `just infra net-verify` there, set
   `egressNsgEnforce = 'off'` in your parameter file before **any** full template apply — including
   step 6 of [Upgrading to the LLM spend controls](#upgrading-to-the-llm-spend-controls) if that
   apply ships this template, and before the apply that creates the second certbot job in
   [Upgrading to hosted-app containment](#upgrading-to-hosted-app-containment) when that template
   ships the firewall-tier platform lists. Also decide `deployNetprobe`: the probe job and its two log alerts
   deploy by default (`deployNetprobe` true, requires `deployApps`), and the no-recent-success alert
   fires until the first scheduled or on-demand run.

   Any full apply of this template changes more than the NSG, even with `egressNsgEnforce = 'off'`:
   it deploys the `<prefix>-netprobe` job and its alerts (unless `deployNetprobe = false`), sets
   threat intelligence to `Deny` on firewall installs (`threatIntelMode`), adds `login.microsoft.com`
   to the egress platform firewall list (Key Vault references), excludes the probe's canary host from
   the firewall-denial alert query, and sets `EGRESS_EXTRA_BLOCKED_CIDRS` on the egress container.

1. **Scratch copy first.** Test NSG attachment on a non-production copy of the install. Resolve
   hypothesis rows with `just infra net-verify` and fill the ADR-0005 probe table in the repository.

2. **Application layer.** Roll the next egress image with a scoped `az containerapp update` (same
   shape as [Roll the apps](#2-roll-the-apps) above). `EGRESS_EXTRA_BLOCKED_CIDRS` arrives with the
   first full template apply, not with the image roll alone.

3. **Non-80/443 origins.** Audit live manifests for approved fetch origins on other ports; they stop
   working once `egressNsgEnforce=enforce` and the closing deny is active.

4. **Private-endpoint pinning.** For new installs set `pinPrivateEndpointAddresses=true`. On an
   existing install list current endpoint addresses (`az network private-endpoint list`), pick
   non-clashing values for `privateEndpointAddresses`, then enable pinning — Azure may require
   recreating endpoints (**unverified in Azure**).

5. **NSG `deny-list-only`.** Apply the template with `egressNsgEnforce=deny-list-only`, then verify
   `/health`, a proxied fetch, an LLM call, a connection-secret read, edge→egress `/health` from inside
   the edge replica (the probe cannot test inbound rules), and `just infra net-verify`.

6. **`enforce`.** Once the probe is green **and** edge→egress `/health` returns 200, move one install
   at a time to `egressNsgEnforce=enforce`.

7. **Subnet recreation fallback.** If a populated subnet cannot take an NSG as a plain update,
   recreating the egress environment is the documented disruption — schedule it.

8. **Accepted-risk record.** In the deployments repo, point the firewall-off acceptance at the
   `netControls` deployment output and the last successful `egress.netprobe_result` instead of
   duplicating posture in prose.

**Existing firewall installs:** `egressFqdnMode` stays `any` on template upgrade unless your
parameter file sets `allowlist`; `threatIntelMode=Deny` can ship on apply. Flipping to `allowlist`
requires maintaining `egressAllowedFqdns` (use `just infra egress-hosts`).

## Upgrading to the tightened image policy

0. **Hold enforcement until you have read the Violations screen.** Until you have reviewed CSP
   reports there, set `imgSrcReportOnly = true` in your parameter file before rolling the edge
   image or running **any** full template apply. That restores the measurement window: open
   enforced `img-src` plus a Report-Only tightened policy. A hand-set
   `EDGE_IMG_SRC_REPORT_ONLY=true` on the edge Container App works only until the next full apply —
   the template re-declares the variable from the params file, so once any apply follows, the flag
   must live in the parameter file, not only on the Container App.

1. **Audit approved origins that will drop out of CSP.** Before you turn enforcement on, run this
   read-only query against the install's database and fix or pre-grant anything you still need.
   It lists `externalOrigins` entries that are not `https:` or `wss:`, or that use a wildcard host
   (both are omitted from `connect-src` / `img-src`). Origins whose hostname contains characters
   outside `[a-z0-9.-]` (aside from IPv6 literals) are dropped too — inspect those manually in
   `capabilities.externalOrigins` if any app relied on them.

```sql
SELECT slug, o FROM apps, jsonb_array_elements_text(COALESCE(capabilities->'externalOrigins','[]'::jsonb)) o
 WHERE o !~* '^(https|wss)://' OR o LIKE '%*%';
```

   Column and JSON paths match `apps/portal/prisma/schema.prisma` (`App.capabilities`); validate
   on your database before you rely on it in production.

2. **Measurement window.** With `imgSrcReportOnly = true` applied (parameter file or scoped
   `az containerapp update --set-env-vars`), roll the edge image. Read the Violations screen and the
   `helix.edge.csp_reports` counter for the window (`disposition=report` while the flag is on).
   Pre-grant legitimate image hosts per app, or list operator-trusted hosts in `EDGE_IMG_SRC_EXTRA`
   — never an image proxy. Tell app owners to inline images or ship them in the bundle.

3. **Enforce.** Remove `imgSrcReportOnly` from the parameter file (or set it false) and apply the
   template, or set `EDGE_IMG_SRC_REPORT_ONLY=false` with a scoped
   `az containerapp update --set-env-vars`. That switches the enforced header to
   `img-src 'self' data: blob:` (plus approved origins and extras) and `object-src 'none'`. No
   further image roll is required unless you are also shipping new edge code. One-org installs that
   accept the open image channel set `EDGE_IMG_SRC_ALLOW_ALL=true` instead of enforcing the tight
   default.

Passing these parameters through Container Apps on a live install is **unverified in Azure**.

## Upgrading to hosted-app containment

These notes cover the three containment parts shipped together: response-header stripping,
tightened CSP, and the optional apps/control domain split. Nothing runs automatically — you choose
the order and parameter values.

0. **Applies to all three parts.** Before rolling the edge image or running any full template apply
   in this release:

   - Set `imgSrcReportOnly = true` in your parameter file ([image policy step
     0](#upgrading-to-the-tightened-image-policy)).
   - Keep `egressNsgEnforce = 'off'` until the scratch-copy test passes ([network controls step
     0](#upgrading-to-the-network-controls)).

### Part 3 — proxied response headers

Deploy the new egress and edge images after step 0; the header blocklist itself needs no setting.

The edge strips a fixed blocklist of response headers on every `/_api/fetch/*` response (the list lives
in `packages/shared/src/fetch.ts`). Browsers do not act on a `Link` header in a `fetch()` response,
so `link` is deliberately **not** stripped — pagination that relies on `rel="next"` keeps working. If
an upstream vendor expected one of the other stripped headers to reach app JavaScript (unlikely), the
blocklist is the single source of truth.

### Part 2 — CSP (`img-src` / `object-src`)

Follow [Upgrading to the tightened image policy](#upgrading-to-the-tightened-image-policy): step 0
(`imgSrcReportOnly = true`) before any edge roll or full apply that ships the measurement mode (one
edge image; the flag selects the mode); then the Violations screen and `helix.edge.csp_reports`
(`disposition=report` during measurement); then enforce (remove the flag or set
`EDGE_IMG_SRC_REPORT_ONLY=false`). Pre-grant per app or list operator-trusted image hosts in
`EDGE_IMG_SRC_EXTRA` — never an image proxy that fetches attacker-chosen URLs. One-organization
installs that accept the open channel set `EDGE_IMG_SRC_ALLOW_ALL=true`. Parameter names in Bicep:
`imgSrcExtra`, `imgSrcReportOnly`, `imgSrcAllowAll`.

### Part 1 — domain split

**New install**

1. Choose two domains, or one domain plus a delegated subdomain you will list on the Public Suffix
   List (**operator-run**; without that entry the two remain the same site and host-only cookies do
   not stop a `Domain=` cookie from reaching the control hosts). The template creates both DNS zones
   in step 2; delegate each at its parent from the `dnsNameServers` and `hostedDnsNameServers`
   deployment outputs (**operator-run**) before running the certbot jobs.
2. Set `appsDomain` (the **control** domain: `auth.`, `portal.`, `dev-api.`), `hostedAppsDomain`
   (the apps domain), and `hostedAppsLive = true` in the parameter file. Deploy with
   `wildcardTlsBound` and `hostedAppsTlsBound` `false`.
3. On a firewall install, apply the release that carries the per-subnet platform FQDN lists (ACME,
   Resource Manager, Entra) **before** the apply that creates the second certbot job, or issuance can
   fail silently (**operator-run**; prerequisite from the network-controls work).
4. Run the first certbot job (`<namePrefix>-certbot`), then the second (`<namePrefix>-ap-certbot`);
   flip both bound flags and redeploy. The TLS what-if canary must never show
   `Delete properties.configuration.ingress.customDomains` for either binding (**unverified in Azure**
   with two bindings on one Container App). Confirm the `edge-health-apps` availability test is green
   once `hostedAppsTlsBound` is on.
5. Register Entra redirect URIs for the control domain as in [Entra setup](/deploy/entra-setup).
6. Submit the apps zone to the Public Suffix List when it is a delegated subdomain (**operator-run**).

**Existing install — keep the current domain as control** (sign-in, portal, dev-api, Entra and vendor
callbacks stay put; only app URLs move)

0. Complete [step 0](#upgrading-to-hosted-app-containment) above before rolling the edge image or
   running any full apply.
1. Deploy new edge and portal images with all split settings absent; confirm a no-op before changing
   parameters.
2. **Provision.** Set `hostedAppsDomain` and keep `hostedAppsLive = false`, then apply. Read the
   deployment output `hostedDnsNameServers` and delegate the apps zone at the parent
   (**operator-run**). On a firewall install, apply the release with the per-subnet platform FQDN
   lists before the apply that creates the second certbot job. Start `<namePrefix>-ap-certbot` once
   delegation resolves publicly; check from outside that `https://www.<hostedAppsDomain>/health`
   answers over HTTPS with a valid certificate. Set `hostedAppsTlsBound = true`, apply, run the TLS what-if canary for both bindings, and
   confirm the `edge-health-apps` availability test is green (**unverified in Azure**).
3. **Verify.** Run the cross-browser sign-in check (Chrome, Firefox, Safari) on a **separate staging
   install** configured like the scratch copy in [network controls step
   1](#upgrading-to-the-network-controls), with `hostedAppsLive = true` and the same domain shape.
   The edge moves all apps or none, so this production install cannot host one staging app on the new
   domain while the rest stay on the old hosts. Tracking-protection heuristics may treat an auth host
   that redirects without a click as a bounce tracker — symptom: login loop at `/start`, visible in
   the `helix.session.gate_denied` counter and the `helix.auth.handoff.complete` span (**unverified in
   Safari, Firefox and Chrome on real domains**).
4. **Cut over.** Set `hostedAppsLive = true` and `legacyAppRedirect = true` in one apply. Bicep sets
   `EDGE_BASE_DOMAIN`, `EDGE_CONTROL_DOMAIN`, `APP_PUBLIC_BASE`, `CONTROL_PUBLIC_BASE`, and
   `EDGE_LEGACY_APP_REDIRECT` from that parameter pair, so the edge, portal, and dev gateway flip
   together.
5. **Operator check after cutover.** `GET /api/v1/providers` (authenticated) must list
   `callbackUrl` exactly `https://auth.<EDGE_CONTROL_DOMAIN>/connections/callback` — the only way to
   catch an edge/portal mismatch the portal cannot detect at boot alone.
6. Tell app owners URLs changed; update `availabilityExtraTargets` (it holds app URLs) and any
   external registration by old host.
7. **Sunset.** Watch `helix.edge.legacy_app_redirects`. When `redirected` has been near zero for your
   chosen period: set `legacyAppRedirect` to `false` and re-apply; delete the control zone's `*` A
   record by hand (a re-apply does not delete DNS records); **keep** the edge's `*.<control domain>`
   binding — `auth.<control domain>` terminates TLS through it and certbot re-binds it on every run;
   keep the `auth`, `portal`, and `dev-api` records.

**Rollback (cutover).** Set `hostedAppsLive` back to `false` and apply. The template omits the
split-only environment variables and replaces each app's env list whole, so the edge, portal, and dev
gateway revert to the single-domain values while the apps zone and second certbot job stay (incremental
mode). Sessions minted on the new app hosts are lost. The legacy redirect is a `307` with `no-store`,
so browsers do not cache it and a rollback stays clean. Leave `hostedAppsDomain` set if you plan to
retry cutover without reprovisioning DNS and TLS.

**Data migration:** none — apps are keyed by slug and id.

**Compatibility:** sessions on old hosts are lost; handoff tokens in flight at cutover fail; browser
state on the old origin does not carry over; `/_api` clients that hard-coded the old host break
(relative URLs are correct); the grace redirect softens GET navigations only.

Split topology on Azure (**unverified in Azure** until exercised on your install): two wildcard
certificates, two certbot jobs, two declarative bindings when both TLS gates are on. New split installs
never create a `*` A record in the control zone; whether Container Apps still binds and re-binds
`*.<control>` without that record is not documented — check the first certbot run.

## What a rollout actually does

These behaviours were measured on a live install, polling an app every ~2 s
while it was pointed at a deliberately broken image. Read this section before
building any release automation.

1. **A bad tag fails the CLI call.** Container Apps validates the image
   manifest synchronously, so `--image <unpullable-tag>` returns an error and
   creates no revision. The app is untouched. "Bad tag" is not a rollout
   failure; it is a failed API call.
2. **A broken rollout causes no downtime.** In `Single` revision mode the old
   revision keeps serving until the new one is `Running`/`Healthy`, and is
   deprovisioned only then. Pointed at an image that exits immediately:
   **0 non-200 responses out of 116 samples.** Note that `ingress.traffic` was
   `latestRevision: true, weight: 100` throughout — traffic config expresses
   intent, not what happens before readiness.
3. **There is no automatic rollback.** The broken revision just sits there.
4. **So a failed rollout is silent.** The app stays up serving the *previous*
   code and nothing surfaces it.

::: warning The failure mode to design against
Points 3 and 4 plus migrate-first give the real hazard: **new schema, apps
quietly running old code.** Nothing is down, nothing alerts, and the install
looks healthy.
:::

For a release pipeline the consequence is: health verification is not there to
prevent an outage — Container Apps already prevents it. Its only job is to
answer one question: did the new code go live? Report that, but do not gate on
it — failing the workflow neither rolls back nor holds traffic.

## Rolling back

Roll forward to the previous tag. It is the same scoped command, and it is why
`sha-` tags are worth deploying:

```bash
az containerapp update -g <rg> -n <namePrefix>-edge \
  --image ghcr.io/<owner>/helix-edge:<previous-sha-tag>
```

**Migrations do not roll back** — they are forward-only by design. A schema
change that the old code cannot tolerate has to be rolled forward with a fix,
so keep migrations backward-compatible with the release before them and the
rollback stays a one-liner.

## A release can be two halves

CI ships app code; the template ships configuration. A change that needs
**both** — a new environment variable that new code reads is the common case —
sits half-deployed until someone applies the template, and nothing alerts on
it: every status is green, because nothing is broken, only inert. The tell
before assuming a release is fully out:

```bash
git diff <deployed-template-commit>..<current> -- infra/azure/
```

If the diff adds or changes a runtime value, the template apply is part of
shipping the change, not follow-up. And when the live-state delta really is
one knob, prefer the scoped `az containerapp update --set-env-vars` — it
converges toward the template (it writes exactly what the template computes),
so the next full apply is a no-op on it.

## Rotating a secret

Platform secrets live in the platform vault, and the apps hold versionless Key
Vault **references** to them — so rotation starts at the vault, not at the app
and not at the template. The vault's public network is off, but ARM
management-plane writes bypass the data-plane firewall, so a write works from
anywhere with a throwaway template:

```bicep
// rotate-secret.bicep
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: '<platformVaultName>'
}
resource rotated 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: '<secret-name>'              // e.g. edge-auth-secret
  properties: { value: '<new-value>' }
}
```

```bash
az deployment group create -g <rg> -n rotate-<secret-name> \
  --template-file rotate-secret.bicep
```

(Note the direction of that write: ARM can *create and update* vault secrets
from anywhere, but it cannot *delete* them — deletion is data-plane only,
i.e. from inside the VNet.)

Then the new value reaches the apps on one of three clocks — these were
measured on a live install, and they differ enough to be worth knowing
precisely:

- **Do nothing: within ~30 minutes.** Container Apps' background refresh
  notices the new vault version and restarts the revisions itself (observed:
  22 min). This is the normal path for singleton secrets.
- **Force it now:** force a new revision, which re-resolves its references at
  provisioning:

  ```bash
  az containerapp update -g <rg> -n <app> --revision-suffix <something-new>
  ```

- **`az containerapp revision restart` does NOT work.** A manual restart
  reuses the secret snapshot stored with the revision and keeps serving the
  old value. Verify a rotation with the resolved value, never with a restart:

  ```bash
  az containerapp secret show -g <rg> -n <app> --secret-name <name>
  ```

One exception to "start at the vault": **never rotate the Postgres admin
password out of band.** `az postgres flexible-server update --admin-password`
drifts from the copy in Key Vault that the migrate job reads, and migrations
start failing. The `postgresAdminPassword` parameter sources from the vault,
so override it for one apply — the server and the vault copy move in the same
pass:

```bash
az deployment group create -g <rg> -f main.bicep -p main.bicepparam \
  --parameters postgresAdminPassword="$NEW_PASSWORD"
```

A role password (`helix_edge` &c.) rotates the other way around: change it in
Postgres first (`ALTER ROLE` via a throwaway in-VNet job — see
[Database & migrations](/deploy/database#troubleshooting)), then write the
rebuilt DSN to the vault secret (`<role>-database-url`) with the template
above. The apps pick it up on the refresh clock.

Three more values whose blast radius is worth knowing before you reach for
them:

- **`HELIX_PORTAL_SECRET` is the encryption key for shared-password app
  material.** Rotating it strands everything already encrypted with it. If the
  actual goal was to capture a value that was never recorded at install,
  recover it from the running install instead — rotation is the harmful move,
  not the recovery: `az containerapp secret list -n <app> --show-values`.
- **`HELIX_EDGE_AUTH_SECRET` signs session cookies.** Rotating it invalidates
  every live session — every user on every app signs in again.
- **`HELIX_INSTRUCTION_SECRET` is shared by the edge and the egress service.**
  Both reference the *same* vault secret, so they converge on their own — but
  the background refresh can take up to ~30 min, and a mismatch between the
  planes fails every attested edge→egress call for the duration. Write the
  vault, then force a new revision on **both** apps back-to-back so the window
  is seconds, not half an hour.

## When you do need a full apply

Anything the template owns and no scoped command can reach:

- Adding or removing a resource — a feature gate like `deployFoundry`,
  `deployAlerts`, `deployDevGateway`, `deployFirewall`.
- Changing a role assignment, an identity, or the network shape.
- Changing a secret that other resources derive from.
- Adding a hostname that needs a TLS binding. **The declared set is an
  allowlist**: a hostname bound by hand is deleted by the next apply with no
  self-heal, so a host that needs a binding gets a row in `main.bicep`.

Before an apply that pulls in new template commits, also compare the live
Postgres major version against the module default: `postgresVersion` is
deliberately not a `main.bicep` parameter — the module default is the only
control — so a template bump can drive an in-place major-version upgrade you
did not schedule.

A full apply is a documented operation, not a blocker. But it has hazards no
preview will show you — read the rest of this section before running one.

### Reconcile the image tag, or the apply rolls you back

`imageTag` is a template parameter, so **the apply deploys whatever your params
file says** — including a tag older than what is running. Params files drift
behind installs, and this is how a routine apply silently downgrades every
workload. Check what is live before you apply:

```bash
az containerapp list -g <rg> \
  --query "[].{app:name,image:properties.template.containers[0].image}" -o table
```

### The vault is the secrets source — there is nothing secret left to source

Before 2026-09-17 this section warned that an unset secret environment
variable rendered as `''` and overwrote the live credential. That failure mode
is gone: the params source every secret from the platform vault with
`az.getSecret()`, resolved server-side at ARM, so an apply needs **no secret
on hand at all**, and a missing vault secret fails the deployment at parameter
evaluation rather than blanking anything. The pre-apply checks that remain are
structural: the vault's `enabledForTemplateDeployment` flag is on (the
template sets it), every referenced secret exists and is enabled, and your
deploy principal holds `Microsoft.KeyVault/vaults/deploy/action` (Owner and
Contributor both include it).

The blindness itself has not gone away, though: the apps' secrets array is a
secure parameter and still renders as `[unknown()]` in a what-if, so the
preview cannot show what any reference resolves *to* — only that the wiring is
intact.

### Read the what-if, knowing what it cannot tell you

```bash
az deployment group what-if -g <rg> -f main.bicep -p main.bicepparam \
  --no-pretty-print
```

Capture the raw JSON — the pretty output cannot be filtered.

**The rule of thumb for false positives: if the `after` side is a literal
`[...]` ARM expression, it is noise.** What-if cannot resolve `reference()`
across nested modules, so it prints the unevaluated expression and reports a
Modify. On a typical install that is roughly a quarter of all leaf deltas,
including every cross-module URL and identity id, DNS record addresses, and
role-assignment principal ids. A second noise class is read-only system
properties the template omits, which show as `Delete` and are never removed.

What the preview genuinely cannot answer:

- **What the secrets resolve to** — the array is a secure parameter and
  renders as `[unknown()]`, as above.
- **Cross-module env values.** A value like the edge's egress URL reports
  Modify unconditionally, so a stale value and a correct one produce the same
  line — one more entry in a large set of lookalike false positives. Verify
  the egress hop against live state after the apply, not against the diff.
- **Rules that gate on cross-module outputs may be omitted entirely** — no
  `Create`, no `Unsupported`, nothing. A defect there surfaces at apply time,
  so count the deployed alert rules afterwards rather than trusting the preview
  in either direction.
- **`deployFoundry=true` makes the whole diff look clean when it is not.** The
  Foundry module takes a `reference()` input, so ARM short-circuits it, and
  the skip cascades: storage, Key Vault, Postgres, DNS and every container app
  drop out of the diff. **Read `diagnostics` before `changes`, and treat a
  container app listed under `Ignore` as a reason to stop.** To get a real
  preview, run the what-if with `-p deployFoundry=false` to see the damage
  surface, then validate the Foundry resources separately as a standalone
  template.

### The TLS canary

On an install with `wildcardTlsBound: true` (and `hostedAppsTlsBound: true` when
`hostedAppsDomain` is set), the what-if must **not** show a delete of
`properties.configuration.ingress.customDomains` for **either** wildcard binding.

**If it does, the gate is off — stop, do not apply.** With the gate on, the
template declares the bindings and an apply preserves them (verified by an
external TLS poll across both apply windows: no strip-then-add gap exists,
because the property is set by the same PUT that reconciles the app). With it
off, the apply strips every bound hostname and browsers immediately fail TLS.

Likely causes, in order: someone edited the params file, someone re-pointed
`using` at an older template, or the parameter got sourced from an environment
variable. It must be a **literal** in the params file — a set-but-blank
variable renders as `''`, which reads as false, and false is the direction
that wipes the bindings.

Do **not** trigger the certbot job as a routine post-apply step. Inside the
renewal window it spends one of Let's Encrypt's five duplicate certificates per
seven days. The job is the fresh-install bootstrap path and the self-heal for an
ungated apply — both exceptional.

### Hand-made role assignments collide

The template names role assignments with a deterministic `guid()`, and ARM
cannot know about a differently-named duplicate — so a hand-made assignment
fails the apply with `RoleAssignmentExists`. It is detectable, because ARM's
`guid()` emits UUIDv5 while `az role assignment create` without `--name` emits a
random UUIDv4, and the version is the first character of the third group:

```bash
for id in $(az identity list -g <rg> --query "[].principalId" -o tsv); do
  az role assignment list --assignee "$id" --all \
    --query "[].{name:name,role:roleDefinitionName,scope:scope}" -o tsv
done | while IFS=$'\t' read -r name role scope; do
  ver=$(echo "$name" | cut -d- -f3 | cut -c1)
  [ "$ver" = "5" ] || printf 'HAND-MADE  %s  %s  %s\n' "$name" "$role" "${scope##*/}"
done
```

Delete the hand-made one and re-apply; the template recreates it identically.
Env-var patches made with `az containerapp update --set-env-vars` are not
affected — env vars are overwritten, not conflicted. Only role assignments
collide.

## After any update

**Control-plane status is not evidence.** `Succeeded`, `Running`,
`runningStatus`, `healthState` and a plausible FQDN have all been green over
real outages. Check the things that fail silently:

- **The active revision carries the tag you deployed** — see
  [step 3](#_3-confirm-the-new-code-is-actually-live).
- **TLS is verified from outside**, which is a different claim from the binding
  existing:

  ```bash
  curl -s -o /dev/null -w '%{http_code} tls=%{ssl_verify_result}\n' \
    https://auth.<appsDomain>/health
  ```

  `tls=0` is a verified chain. With a split install (`hostedAppsLive = true`), also probe
  `https://www.<hostedAppsDomain>/health` the same way.
- **Split installs:** `GET /api/v1/providers` must list `callbackUrl` as
  `https://auth.<control domain>/connections/callback` (same value as `EDGE_CONTROL_DOMAIN` on the
  edge). A mismatch means the portal and edge disagree and vendor OAuth will fail even when both
  services boot.
- **The edge→egress hop resolves**, after any full apply. The apply rewrites
  that URL on every caller from a `reference()` the diff could never resolve,
  so an apply is exactly when this hop breaks. Probe it from inside the
  calling container — it has failed on real applies. `az containerapp exec`
  needs a TTY, and the images carry no curl or wget, so the probe is node over
  a pseudo-TTY:

  ```bash
  script -q /dev/null az containerapp exec -n <namePrefix>-edge -g <rg> --command \
    "node -e \"fetch(process.env.EDGE_EGRESS_URL+'/health').then(r=>console.log(r.status)).catch(e=>console.log('ERR',e.cause?.code))\"" < /dev/null
  ```

  Expect `200`. `ENOTFOUND` means the environment's private DNS zone is wrong;
  a 404 serving Azure's "Container App - Unavailable" page means the URL (or
  the ingress scope) is stale.
- **Alert rules still exist**, after a full apply — a rule that failed to deploy
  looks exactly like a healthy platform.
- **A request traces end to end.** Drive a real request through a deployed app
  and check it lands in Application Insights. Wait out ingestion latency
  before concluding anything: an empty result is not evidence of failure until
  the latency has passed. When a query comes back empty, suspect the query
  first — wrong workspace, wrong table, wrong schema. There are two Log
  Analytics workspaces per install, so **never index them by position**.
- **Network controls after a networking change.** If the update touched NSG,
  firewall, or private-endpoint parameters, run `just infra net-verify` and read
  any failing `egress.netprobe_check` lines in the **egress** workspace
  (**unverified in Azure** until you have run it on that install).

### Verification pitfalls

Two traps that have produced clean-looking, wrong answers:

- **`az containerapp logs show --tail` maxes at 300.** A larger value exits
  with an error — and piped into `grep -c`, that error renders as a clean `0`:
  "no warnings in the logs" when in fact no logs were fetched. Before reading
  anything into an *absence*, assert the fetch was non-empty.
- **The actionable error from a failed apply may exist only in stderr.** A
  resource-provider preflight rejection can surface as `InvalidTemplateDeployment
  … See inner errors for details` in the deployment-operations view and the
  activity log, while the real line sits three `details` levels deep in the
  `az deployment group create` stderr payload. Capture the raw stderr of a
  failed apply before chasing it through the operations view, which is not a
  superset of it.
