# Helix feature docs

> **Related ADRs:** [ADR-0001](../adr/0001-three-runtime-split.md) (three-runtime split) · [ADR-0012](../adr/0012-edge-portal-codeploy.md) (edge/portal co-deploy).

These documents describe shipped features: behavior, implementation files, and
known gaps. Update them with the code. Architecture decisions live in
[ADRs](../adr/); the [architecture](../platform-architecture.md) explains the
system design, and the [project plan](../platform-project-plan.md) tracks status.
References such as “§4.2” point to the architecture unless another document is named.

Helix runs on Azure and locally. Its three services separate app traffic (edge),
administration (portal), and outbound requests with credential injection (egress).
See [the tour](../../TOUR.md) for the security boundaries and repository map.

## Features

| Doc | Feature | Lives in |
| --- | --- | --- |
| [edge-serving.md](./edge-serving.md) | Host routing, registry projection, Blob streaming, CSP, 404/410 | `apps/edge` |
| [authentication.md](./authentication.md) | App-user OIDC flow, sessions, the per-request gate, portal bearer JWTs | `apps/edge`, `apps/portal` |
| [llm-gateway.md](./llm-gateway.md) | `POST /_api/llm/chat` + the OpenAI-compatible surface — metered, allowlisted, key-hiding LLM proxy with structured output | `apps/edge` |
| [app-data-gateway.md](./app-data-gateway.md) | `/_api/data/*` user / collection / shared storage + owner drain | `apps/edge`, `apps/portal` |
| [fetch-proxy.md](./fetch-proxy.md) | `/_api/fetch/<url>` — governed outbound HTTP via the `helix-egress` plane | `apps/edge`, `apps/egress` |
| [network-controls.md](./network-controls.md) | Egress NSG, optional firewall, application block list, network probe | `apps/egress`, `infra/azure` |
| [secrets-and-connections.md](./secrets-and-connections.md) | Connection secrets: sealed credentials injected server-side | `apps/portal`, `apps/egress`, `packages/secret-store` |
| [connection-providers.md](./connection-providers.md) | OAuth connection providers: the admin catalog, import/export, My Connections | `apps/portal`, `apps/egress` |
| [dev-mode.md](./dev-mode.md) | Develop an app against an isolated `env=dev` tier via the dev-gateway | `apps/edge`, `apps/portal` |
| [registry-and-deploys.md](./registry-and-deploys.md) | App CRUD, version lifecycle, zip upload, promote/rollback, archive | `apps/portal` |
| [capabilities-and-manifests.md](./capabilities-and-manifests.md) | The per-app manifest the gateway enforces | `packages/shared`, `apps/portal` |
| [cli.md](./cli.md) | The `helix` CLI: deploy + OIDC device-flow login | `packages/cli` |
| [portal-web.md](./portal-web.md) | The React/Mantine portal SPA | `apps/portal-web` |
| [onboarding.md](./onboarding.md) | The in-app "How to develop" guide + the downloadable agent skill | `packages/deploy-skill`, `apps/portal-web` |
| [dev-idp.md](./dev-idp.md) | The local OIDC issuer used in dev/test | `apps/dev-idp` |
| [visitor-analytics.md](./visitor-analytics.md) | The owner's Visitors view: visits, unique visitors, approximate location | `apps/edge`, `apps/portal`, `apps/portal-web` |
| [observability.md](./observability.md) | Logs, traces and metrics about the platform itself; the OTLP-only boundary | all three services, `packages/telemetry` |
| [examples.md](./examples.md) | Reference apps you can `helix deploy` | `examples/` |

## Milestone map (project plan §4)

- **M0** — skeleton, boot pattern, `/health`.
- **M1** — registry + deploys (portal API + `helix` CLI). _Shipped._
- **M2** — edge serving on `*.local.helix.azxlabs.io`, registry projection, Blob streaming, CSP, 404/410. _Shipped._
- **M3** — auth: OIDC handoff, sessions, the gate, CLI/portal bearer tokens, **local issuer**. _Shipped (local half); real Entra registration is the remaining tail._
- **M4** — gateway v0: the LLM proxy, then app-data, metering, and the DB role split. _Shipped locally._
- **M4.5** — the `helix-egress` mechanism plane: fetch-proxy + secret-backed connections. _Shipped locally — this milestone._
- **M5** — Azure deploy + pilot. _Ahead._

Each doc has a **Planned / not yet built** section calling out what is deferred or config-only.
The portal SPA's screens are all real and wired to `/api/v1/*`; the one not-yet-built sub-feature
(per-app RBAC roles) carries a `PreviewBadge` (`milestone="v1"`) and is never silently faked.
