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

Defaults are the strict or upgrade-conservative values in `infra/azure/main.bicep`. Relax only with a documented operator decision.

| Knob | Default | Strict vs relaxed |
| --- | --- | --- |
| `EGRESS_EXTRA_BLOCKED_CIDRS` | Set by template to `vnetAddressPrefix` + `100.100.0.0/17` | Strict: blocks the install VNet and ACA infra slice at the application layer |
| `egressNsgEnforce` | `deny-list-only` | Designed not to change platform flows on upgrade: explicit deny rows without the closing deny-all (**unverified in Azure** until `just infra net-verify` and the edge→egress check pass). Strict: `enforce` adds the closing deny-all and the `100.64.0.0/10` row. `off` detaches the NSG |
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
| `netprobeClosingDenyTarget` | empty | Optional `host:port` (not 80/443) to score the closing deny when `enforce` and the firewall is off |

Read the effective posture from the deployment output `netControls` (firewall flag, FQDN mode, NSG mode, extra CIDRs, pinned addresses, probe expectations, `probe.denyProvable`).

`deny-list-only` activates every outbound deny row in `nsg-egress-rules.json` except the closing deny-all (row 4000) and `deny-cgnat` (`100.64.0.0/10`, which is **enforce-only**). Inbound `deny-vnet-in` is also enforce-only so ILB backend traffic from the apps subnet is not dropped on the default path.

## The probe

`apps/egress/src/netprobe.ts` dials forbidden and required destinations from the egress subnet, classifies each attempt (`blocked`, `reachable`, `unresolved`, `error`), and prints JSON lines `egress.netprobe_check` (per check) and `egress.netprobe_result` (summary with `ok`, `denyProven`, and `closingDenyProven`). **The probe tests outbound paths only** — a green `egress.netprobe_result` does not prove edge→egress or portal→egress inbound through the internal load balancer; run the edge→egress `/health` check in `infra/azure/README.md` after apply.

**What a green probe proves.** `ok: true` means every scored check matched its expectation. That is necessary but not sufficient for NSG proof: `denyProven` is `true` only when the NSG expectation is not `off` and a scored in-VNet deny check ran and matched (today `blob-pe-443` when `PROBE_PE_ADDRESSES=pinned`). On the default unpinned install the scheduled job still reports `ok: true` with `denyProven: false`; `just infra net-verify` exits **3** with guidance to enable pinning. The closing deny is proven only when `netprobeClosingDenyTarget` is set, `egressNsgEnforce=enforce`, and the firewall is off (`closingDenyProven: true`). Port checks against the allowed host (25, 22, 8443) are informational in every mode — they cannot distinguish NSG posture. Nothing here is verified in Azure until an operator runs `net-verify` on that install.

Wire-server (`168.63.129.16`) and IMDS checks are **informational in every mode**: Microsoft documents that prefix-based NSG rules do not filter WireServer on ports 80 and 32526 unconditionally, and filter DNS to `168.63.129.16` only when targeted with the `AzurePlatformDNS` service tag ([Container Apps firewall integration](https://learn.microsoft.com/en-us/azure/container-apps/firewall-integration), [168.63.129.16](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16)); `ssrf.ts` is the only control on `168.63.129.16` for proxied traffic (there is no NSG deny row on that address).

`PROBE_PE_ADDRESSES` is `pinned` when `pinPrivateEndpointAddresses` is true (15 checks) or `dynamic` when off (11 checks — private-endpoint rows omitted). Expectations depend on `PROBE_EXPECT_NSG`, `PROBE_EXPECT_FIREWALL`, and `PROBE_EXPECT_FQDN_ALLOWLIST` (wired from `netControls`).

When `PROBE_PE_ADDRESSES=pinned` and the NSG is not `off`:

| Check id | Expected |
| --- | --- |
| `kv-platform-443` | `reachable` (egress Key Vault references to kv-platform) |
| `kv-connections-443`, `kv-delegated-443` | `reachable` |
| `blob-pe-443` | `blocked` when NSG is on; informational when `off` |
| `postgres-5432`, `public-allowed-443`, `dns-resolve` | `reachable` |
| `public-canary-443` | `blocked` when FQDN allow-list is on; else `reachable` |
| `public-port-25`, `public-port-22`, `public-port-8443` | `informational` (cannot prove NSG deny rows) |
| `closing-deny` | `blocked` when `enforce` and firewall off, if `PROBE_CLOSING_DENY_TARGET` is set; else omitted |
| `wire-server-*`, `imds-80`, `apps-env-443` | `informational` |

| Recipe | Purpose |
| --- | --- |
| `just infra net-sim` | Local iptables simulation of `nsg-egress-rules.json` on a Docker host (**not** the dev container). `just infra net-sim --static` runs translator tests only. |
| `just infra net-verify <resource-group> [prefix]` | Start `<prefix>-netprobe` in Azure, wait, print probe lines; exit **1** on `ok=false`, **3** when NSG is on but `denyProven=false` (**unverified in Azure** until an operator runs it). |
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

- **Postgres, kv-connections, kv-delegated, and kv-platform** — NSG and firewall rules must allow them. Egress loads its own secrets from kv-platform through Key Vault references fetched from `snet-egress`, so the NSG must allow kv-platform when pinning is on. The egress identity holds Key Vault Secrets User on the whole kv-platform vault, so the network layer cannot stop an egress compromise from reading platform secrets; per-secret role assignments or a separate egress-only vault is the real fix (deferred in `TODO.md`). A bare HTTP request without an injected credential is still limited by the application filter.
- **Exfiltration to a host the allow-list must permit** — when `egressFqdnMode=allowlist`, any hostname in `egressAllowedFqdnsEffective` remains reachable on allowed ports.
- **DNS tunnelling** — not in scope of the NSG/FQDN rules described here.
- **Lateral movement on `snet-apps`** — edge, portal, and dev-gateway share one subnet; an NSG there cannot separate them (deferred).

## Planned / not yet built

See [TODO.md](../../TODO.md) (network egress deferred items): NSG on `snet-apps`, generated allow-list reconciled from approvals, portal note for firewall operators when approving new origins, optional bounded `ssrf.reason` span attribute on egress.

## Unverified in Azure

Until an operator records results in [ADR-0005](../adr/0005-ssrf-egress-controls.md) (probe table), treat these as open:

| Topic | Why |
| --- | --- |
| NSG attach on a populated Container Apps subnet | Azure may reject late association |
| Platform-flow allow rows (MCR, Front Door, Entra, Monitor, ILB) | Marked `hypothesis` in rule JSON |
| `deny-cgnat` (`100.64.0.0/10`) on `enforce` | Enforce-only row; hypothesis until net-verify |
| Replica behavior at `168.63.129.16` / IMDS | Informational probe checks |
| Do edge and portal reach egress through the internal load balancer on 31080 and 31443 with the NSG on? | Inbound ILB backend ports; not covered by the probe |
| Edge→egress source IP seen by NSG | Inbound rule hypothesis |
| Static private-endpoint `ipConfigurations` | API and update semantics |
| Firewall runtime (SNI-only rules, collection limits, post-handshake drop, threat intel on SKU) | Template declares; probe uses TLS handshake assumption |
| Diagnostic tables for firewall and probe alerts | KQL column names |
| `just infra net-verify`, `egress-hosts` inside portal replica | Operator procedures |

## Operator rollout notes

1. **Scratch copy first.** Test NSG attachment on a non-production copy of the install. Resolve hypothesis rows with `just infra net-verify` and fill the ADR-0005 probe table.
2. **Application layer.** Roll the next egress image with a scoped `az containerapp update` (see the operator updates doc, "Roll the apps"). `EGRESS_EXTRA_BLOCKED_CIDRS` arrives with the first full template apply.
3. **Non-80/443 origins.** Audit live manifests for approved fetch origins on other ports; they stop working once `egressNsgEnforce=enforce` and the closing deny is active.
4. **Private-endpoint pinning.** For new installs set `pinPrivateEndpointAddresses=true`. On an existing install list current endpoint addresses (`az network private-endpoint list`), pick non-clashing values for `privateEndpointAddresses`, then enable pinning — Azure may require recreating endpoints (**unverified in Azure**).
5. **NSG `deny-list-only`.** Apply the template with `egressNsgEnforce=deny-list-only`, then verify `/health`, a proxied fetch, an LLM call, a connection-secret read, edge→egress `/health` from inside the edge replica (the probe cannot test inbound rules), and `just infra net-verify` (must show `denyProven: true` — enable pinning first if the recipe exits 3).
6. **`enforce`.** Once the probe is green with `denyProven: true` and edge→egress `/health` returns 200, move one install at a time to `egressNsgEnforce=enforce`. Optionally set `netprobeClosingDenyTarget` on a firewall-off scratch copy to record `closingDenyProven: true` before relying on the closing deny in production.
7. **Subnet recreation fallback.** If a populated subnet cannot take an NSG as a plain update, recreating the egress environment is the documented disruption — schedule it.
8. **Accepted-risk record.** In the deployments repo, point the firewall-off acceptance at `netControls` and the last successful `egress.netprobe_result` instead of duplicating posture in prose.

**Existing firewall installs:** `egressFqdnMode` stays `any` on template upgrade; `threatIntelMode=Deny` can ship on apply. Flipping to `allowlist` requires maintaining `egressAllowedFqdns` (use `just infra egress-hosts`). Before enabling the firewall on an install that never ran it, ensure apps-subnet platform hosts are in the template lists (**unverified in Azure** for your tenant).

**Compatibility breaks:** `enforce` blocks outbound internet except allowed ports and platform rows; `allowlist` blocks FQDNs not in the effective list; pinning changes private-endpoint IPs; threat-intel `Deny` may block a vendor IP (use firewall logs, revert to `Alert`).
