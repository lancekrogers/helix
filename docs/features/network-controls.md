# Network egress controls

> **Related ADRs:** [ADR-0005](../adr/0005-ssrf-egress-controls.md) (SSRF + network amendment) · [ADR-0001](../adr/0001-three-runtime-split.md) (egress-only zone) · [ADR-0028](../adr/0028-deployment-model-customer-deployed.md) (per-install settings) · [ADR-0046](../adr/0046-azure-ai-foundry-keyless-llm-backend.md) (Foundry on the firewall allow-list).

Outbound traffic from hosted apps is governed at the fetch proxy ([fetch-proxy.md](./fetch-proxy.md)) and at the network edge. This page describes the four layers the Azure template ships, how to read declared posture, and how to roll them out. Nothing here replaces the operator's deployments repo for accepted-risk records — point those at the `netControls` output and the last `egress.netprobe_result`.

| Layer | What | Every install? |
| --- | --- | --- |
| 1 Application | `apps/egress/src/ssrf.ts` + `EGRESS_EXTRA_BLOCKED_CIDRS` | Yes |
| 2 NSG | `snet-egress` rules from `nsg-egress-rules.json` (`egressNsgEnforce`) | Yes (unless `off`) |
| 3 Firewall | FQDN mode, threat intel, platform lists (`deployFirewall`) | Only when firewall deployed |
| 4 Probe | `<prefix>-netprobe` job → `egress.netprobe_*` logs | Default on (`deployNetprobe`) |

## Per-install settings

Defaults are the strict or safe-on-upgrade values in `infra/azure/main.bicep`. Relax only with a documented operator decision.

| Knob | Default | Strict vs relaxed |
| --- | --- | --- |
| `EGRESS_EXTRA_BLOCKED_CIDRS` | Set by template to `vnetAddressPrefix` + `100.100.0.0/17` | Strict: blocks the install VNet and ACA infra slice at the application layer |
| `egressNsgEnforce` | `deny-list-only` | Safe on upgrade: the deny rows without the closing deny-all. Strict: `enforce` adds the closing deny-all. `off` removes the NSG |
| `egressAllowedPorts` | `80`, `443` | Strict: non-standard approved fetch ports need explicit values before `enforce` |
| `pinPrivateEndpointAddresses` | `false` | Relaxed for upgrades: dynamic PE IPs; `true` pins `.4`–`.7` of `snet-pe` (overridable) for tighter NSG rows |
| `privateEndpointAddresses` | Derived when pinning | Overrides per-endpoint IPv4 when pinning is on |
| `vnetAddressPrefix` | `10.0.0.0/16` | Feeds NSG token expansion and `EGRESS_EXTRA_BLOCKED_CIDRS` |
| `deployFirewall` | `true` | Strict reference; `false` removes forced tunnel (live installs may use this) |
| `threatIntelMode` | `Deny` | Strict when firewall on; `Alert` / `Off` relax |
| `egressFqdnMode` | `any` | Relaxed on upgrade; `allowlist` restricts egress internet to product FQDNs |
| `egressAllowedFqdns` | `[]` | Operator additions to allow-list (not generated from approvals) |
| `deployNetprobe` | `true` | The probe job (needs `deployApps`); its two alerts also need `deployInfraAlerts` |
| `netprobeAllowedHost` | `mcr.microsoft.com` | Positive control for registry reachability |
| `netprobeCanaryHost` | `example.net` | Expected blocked when allow-list is on |

Read the effective posture from the deployment output `netControls` (firewall flag, FQDN mode, NSG mode, extra CIDRs, pinned addresses, probe expectations).

## The probe

`apps/egress/src/netprobe.ts` dials forbidden and required destinations from the egress subnet, classifies each attempt (`blocked`, `reachable`, `unresolved`, `error`), and prints JSON lines `egress.netprobe_check` (per check) and `egress.netprobe_result` (summary). Wire-server (`168.63.129.16`) and IMDS checks are **informational in every mode**: Azure documents that prefix-based NSG rules do not filter those host-node paths ([168.63.129.16](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16), [NSG platform considerations](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)); the application block list is the control for proxied traffic.

`PROBE_PE_ADDRESSES` is `pinned` when `pinPrivateEndpointAddresses` is true (15 checks) or `dynamic` when off (11 checks — private-endpoint rows omitted). Expectations depend on `PROBE_EXPECT_NSG`, `PROBE_EXPECT_FIREWALL`, and `PROBE_EXPECT_FQDN_ALLOWLIST` (wired from `netControls`).

| Recipe | Purpose |
| --- | --- |
| `just infra net-sim` | Local iptables simulation of `nsg-egress-rules.json` on a Docker host (**not** the dev container). `just infra net-sim --static` runs translator tests only. |
| `just infra net-verify <resource-group> [prefix]` | Start `<prefix>-netprobe` in Azure, wait, print probe lines (**unverified in Azure** until an operator runs it). |
| `just infra egress-hosts` | List hosts approved apps need on the firewall allow-list; `--check` fails on drift. |

Alerts (`alerts-netprobe.bicep`) read the **egress** Log Analytics workspace. Firewall denial alerts read the **apps** workspace (`firewall-diagnostics.bicep`).

## Implementation files

- `apps/egress/src/ssrf.ts`, `config.ts` — application filter and `EGRESS_EXTRA_BLOCKED_CIDRS`
- `apps/egress/src/netprobe.ts` — probe entry point
- `infra/azure/nsg-egress-rules.json`, `modules/nsg.bicep` — NSG rules
- `infra/azure/modules/firewall.bicep`, `firewall-diagnostics.bicep` — optional firewall tier
- `infra/azure/modules/netprobe-job.bicep`, `alerts-netprobe.bicep` — probe job and alerts
- `infra/azure/main.bicep` — parameters, `netControls` output, probe env wiring
- `infra/netsim/` — local simulation (`translate.mjs`, `run.mjs`)
- `apps/portal/scripts/egress-hosts.ts` — allow-list drift tooling
- `.justfiles/infra.just` — `net-sim`, `net-verify`, `egress-hosts`

## What this does not stop

- **Postgres and the two vaults egress uses** — NSG and firewall rules must allow `kv-connections`, `kv-delegated`, and Postgres; only the application filter and absent credentials limit bare reachability.
- **Exfiltration to a host the allow-list must permit** — when `egressFqdnMode=allowlist`, any hostname in `egressAllowedFqdnsEffective` remains reachable on allowed ports.
- **DNS tunnelling** — not in scope of the NSG/FQDN rules described here.
- **Lateral movement on `snet-apps`** — edge, portal, and dev-gateway share one subnet; an NSG there cannot separate them (decision N5, deferred).

## Planned / not yet built

See [TODO.md](../../TODO.md) (network egress deferred items): NSG on `snet-apps`, generated allow-list reconciled from approvals, portal note for firewall operators when approving new origins, optional bounded `ssrf.reason` span attribute on egress.

## Unverified in Azure

Until an operator records results in [ADR-0005](../adr/0005-ssrf-egress-controls.md) (probe table), treat these as open:

| Topic | Why |
| --- | --- |
| NSG attach on a populated Container Apps subnet | Azure may reject late association |
| Platform-flow allow rows (MCR, Front Door, Entra, Monitor, ILB) | Marked `hypothesis` in rule JSON |
| `100.64.0.0/10` deny vs ingress | Hypothesis row |
| Replica behavior at `168.63.129.16` / IMDS | Informational probe checks |
| Edge→egress source IP seen by NSG | Inbound rule hypothesis |
| Static private-endpoint `ipConfigurations` | API and update semantics |
| Firewall runtime (SNI-only rules, collection limits, post-handshake drop, threat intel on SKU) | Template declares; probe uses TLS handshake assumption |
| Diagnostic tables for firewall and probe alerts | KQL column names |
| `just infra net-verify`, `egress-hosts` inside portal replica | Operator procedures |

## Operator rollout notes

1. **Scratch copy first (N1).** Test NSG attachment on a non-production copy of the install. Resolve hypothesis rows with `just infra net-verify` and fill the ADR-0005 probe table.
2. **Application layer.** Ship the next egress image; no infra change required. The template sets `EGRESS_EXTRA_BLOCKED_CIDRS`.
3. **Non-80/443 origins.** Audit live manifests for approved fetch origins on other ports; they stop working once `egressNsgEnforce=enforce` and the closing deny is active.
4. **Private-endpoint pinning (N2).** For new installs set `pinPrivateEndpointAddresses=true`. On an existing install list current endpoint addresses (`az network private-endpoint list`), pick non-clashing values for `privateEndpointAddresses`, then enable pinning — Azure may require recreating endpoints (**unverified in Azure**).
5. **NSG `deny-list-only`.** Apply the template with `egressNsgEnforce=deny-list-only`, then verify `/health`, a proxied fetch, an LLM call, a connection-secret read, edge→egress `/health` from inside the edge replica (the probe cannot test inbound rules), and `just infra net-verify`.
6. **`enforce`.** Once the probe is green, move one install at a time to `egressNsgEnforce=enforce`.
7. **Subnet recreation fallback.** If a populated subnet cannot take an NSG as a plain update, recreating the egress environment is the documented disruption — schedule it.
8. **Accepted-risk record.** In the deployments repo, point the firewall-off acceptance at `netControls` and the last successful `egress.netprobe_result` instead of duplicating posture in prose.

**Existing firewall installs:** `egressFqdnMode` stays `any` on template upgrade; `threatIntelMode=Deny` can ship on apply. Flipping to `allowlist` requires maintaining `egressAllowedFqdns` (use `just infra egress-hosts`). Before enabling the firewall on an install that never ran it, ensure apps-subnet platform hosts are in the template lists (**unverified in Azure** for your tenant).

**Compatibility breaks:** `enforce` blocks outbound internet except allowed ports and platform rows; `allowlist` blocks FQDNs not in the effective list; pinning changes private-endpoint IPs; threat-intel `Deny` may block a vendor IP (use firewall logs, revert to `Alert`).
