# 0005. Egress SSRF + secret-injection mechanism

**Status:** Accepted
**Related:** ADR [0001](0001-three-runtime-split.md), [0013](0013-egress-trust-model.md); review ISSUE-01, ISSUE-02, ISSUE-09, ISSUE-10

## Context

Egress is the only component that makes outbound calls with injected secrets. It is the platform's single point of contact with the public internet and with attacker-influenced target URLs (an app declares the proxied origin). It must resist SSRF and never let the credential reach the app.

## Decision

Egress (`apps/egress/src/ssrf.ts`, `proxy.ts`) applies, per outbound call:

- Resolve the hostname, **validate the resolved IP** against private/loopback/link-local/IMDS ranges, and **dial the validated IP literal** so there is no second resolution (DNS-rebind defeated).
- Do **not** follow redirects — undici 7 follows a redirect only when a `redirect`
  interceptor is composed onto the dispatcher, and egress composes none (a plain
  `Agent` returns the 3xx verbatim); `Location` is additionally stripped from the
  response by the blocklist so a forwarded redirect can't be chased by the browser
  either (ISSUE-10 resolved, issue #10). `Content-Location` survives but has an
  injected query secret redacted (issue #7).
- Filter headers in both directions — a safelist on the request path; on the response path a *blocklist* plus a **dynamic strip of the exact headers egress injected** (ISSUE-01/#7 resolved — `applyInjection` reports every header name and query param it wrote and the response loop removes them, since per-recipe configured names defeat any static list; `authorization` is also in the blocklist as a backstop, and a secret reflected in `Location`/`Content-Location` is redacted). Inject the resolved secret server-side only.
  - **Amended 2026-08-04 for the `hmac-timestamp` recipe**, which writes *two* headers (a timestamp and a signature), so the report is a list rather than a single name. The signature header is the load-bearing case: its name is configuration, so it can never be in the static blocklist, and only the dynamic strip covers it.
- Stream the response back to the edge with size/time bounds.

## Consequences

- A compromised or malicious app cannot use the proxy to reach internal services or cloud metadata.
- The credential is injected at egress and never returned to the app in a **response header** — the dynamic strip covers arbitrary recipe header names, the blocklist backstops `authorization`, and query secrets are redacted from `Location`. Response-**body** echo (an upstream reflecting the secret into the body) remains an accepted transparent-proxy residual: no header-level filter closes it.
  - For a **derived** recipe (`hmac-timestamp`) that residual cuts both ways, and the net is *worse* than it first appears. What can reflect is a per-timestamp signature, never the private key — better than a static bearer, which reflects a permanent credential. But that signature is a working credential for the upstream's whole clock-skew window against **any** path on the origin, and the app can re-harvest a fresh one on every proxied call, so "short-lived" buys nothing against a persistent app. Spending it bypasses the manifest allowlist, the per-app budget, the instruction's method/path binding, and the `gateway_calls` ledger. Redacting a known-exact token from a streamed body is more tractable here than in general (egress knows the precise string it just minted) — filed, not built, because the same argument applies to `header-bearer` and was declined there.
- The controls are a denylist/validation surface that must be kept current against IP-encoding and redirect tricks.
- The `maxBodyBytes` cap is enforced by a **byte counter over the actual bytes** (`@azx-pbc/shared` `capBody`/`byteCapStream`), not the `content-length` header — so chunked, CL-absent, and lying-`content-length` bodies are all counted (resolves **ISSUE-02**, issue #8). It runs per-direction on both hops (egress `/proxy` and the edge `/_api/fetch` relay), so the planes cap independently. The `content-length` check is retained only as a fast-path. A request-side overflow is refused with **413 `too_large`** before/without completing the upstream call; a response-side overflow **truncates** the already-committed stream (logged out-of-band) — a documented transparent-proxy residual, since status + headers are flushed before the counter can trip.

## Review notes (2026-06-25)

IP-pinning **verified to defeat DNS-rebind** (refuted a reviewer's "socket not pinned" claim — `connectUrlFor()` dials the IP literal). Gaps to close:
- Response-header blocklist omits `authorization`/`www-authenticate` → injected secret echo-back (**ISSUE-01, Critical**).
- Body-size cap is `content-length`-only → chunked-transfer bypass (**ISSUE-02, Critical**).
- IPv6 blocklist gaps: `fe80::/10`, 6to4, NAT64, full-form loopback, hex-mapped v4 (ISSUE-09).
- ~~`maxRedirections: 0` is implicit; `Location` is forwarded so the browser follows it (ISSUE-10).~~ **Resolved (issue #10):** the non-follow is now structural (undici 7 follows redirects only via a composed `redirect` interceptor, which egress omits) and made explicit in code, and `Location` is stripped by the response blocklist.

## Challenge outcome (2026-06-26)

WEAKEN — ISSUE-01/02/09/10 above all re-confirmed; the SNI-preservation refutation holds (`servername: target.hostname`). One **new, undocumented** gap (filed **#11**): egress injects a connection secret over **cleartext `http://`** — `proxy.ts:97-99` accepts `http:`, and secret injection (`:108-121`, `applyInjection`) applies no `target.protocol` guard. Require `https://` on any secret-backed origin. (Response-header safelist → **#7**; body-size cap → **#8**; IPv6 ranges → **#2**.) Also reframe: the IP denylist is defense-in-depth — the network-zone egress allowlist (ADR-0001) is the primary control.

## Hardening note (2026-08-06, the dev seams boot-fail)

Two env flags open controls recorded above: `EGRESS_ALLOW_PRIVATE` (skip the
private/loopback/IMDS denylist) and `EGRESS_ALLOW_INSECURE_CONNECTION` (permit
injecting a connection secret into a cleartext `http://` target — the guard added
for **#11**). Both were documented "false in prod" and neither was enforced, so a
value leaking into a deployed config would have disabled the control **silently**:
nothing fails, every call still works, and the difference surfaces nowhere. That
is the same property the `deployFirewall` note below calls out, on the one plane
that holds plaintext credentials.

`loadConfig` now **refuses to start** when either is true under
`NODE_ENV=production` (`apps/egress/src/config.ts`, covered in `config.test.ts`),
matching the sibling dev seams on the other two planes —
`EDGE_DEV_ALLOW_UNAUTHENTICATED`, `PORTAL_ALLOW_SELF_APPROVE`, and the dev-token
verifier, which refuses to construct. Both flags keep their boot-time `warn` for
the dev case. Neither was ever set in a deployment (checked 2026-08-06); this
closes the way one could be.

## Deployment note (2026-07-23, `deployFirewall`)

The network-zone egress allow-list named here as the **primary control** is
realized on Azure by the Azure Firewall in `infra/azure` (deny-by-default; only
`snet-egress` is allowed out). That firewall is now **operator-optional**
(`deployFirewall`, default `true`) because its ~$900/mo flat cost is an adoption
barrier for a customer-deployed product. **Turning it off removes this ADR's
primary control**, demoting the outbound posture to the app-level `ssrf.ts`
denylist (the defense-in-depth surface described above) and letting the edge
reach the internet directly. This is acceptable only for dev / smoketest /
trusted single-tenant installs; production and untrusted/multi-tenant hosting
must keep it (or an equivalent network egress control). Data-plane privacy
(private endpoints on Postgres/Blob/KV) is independent of the flag. See
`infra/azure/README.md` → "Optional: the egress firewall".

**Accepted-risk record (2026-09-22):** both current production installs run with
`deployFirewall = false` — a deliberate per-install cost decision, verified
structurally (no firewall resource provisioned, route tables empty) rather than
assumed. Both are trusted single-tenant installs, the case this note calls
acceptable; the acceptance, and the preconditions for turning it back on (the
allow-list must also cover the platform's own dependencies — Key Vault and the
Entra login host), live in the operator's private deployments repo. The
"primary control" claim above therefore describes the reference posture, not
the present live one.

**Perf note (Resolved):** egress originally built a **fresh undici `Agent` per request** because the dispatcher carried the per-request pinned IP + `servername` (SNI), which defeated cross-request connection pooling (a TCP+TLS handshake per outbound call) — an accepted simplicity-for-isolation trade. This is now **optimized**: `makeProxyHandler` holds **one long-lived shared `Agent`** (closed on app teardown via a Fastify `onClose` hook) whose connector — built with `buildConnector` — runs `resolveAndValidate` and **pins the socket to the validated IP on every new connection**, then hands off to the default connector with `servername` pinned to the real hostname. The request dials the **real origin** (undici pools by origin and derives Host/SNI from it), so keep-alive is recovered (a `proxy.test.ts` case asserts one TCP connection across six requests). The IP-pin is unweakened: validation runs per *new* socket, a pooled/keep-alive socket is already bonded to a validated IP (so reuse can't reach a rebound address and the next fresh socket re-validates), and a blocked/unresolvable host throws `SsrfBlockedError` from the connector, which undici propagates verbatim to the `request()` rejection where the handler maps it to `403 blocked` — preserving the old upfront-check semantics.

## Amendment (2026-10-10): network controls behind the SSRF filter

### Baseline

Four layers stack behind the per-request controls in this ADR:

1. **Application filter** — `apps/egress/src/ssrf.ts`: private/loopback/IMDS and documentation ranges, install-specific `EGRESS_EXTRA_BLOCKED_CIDRS`, validated-IP dial, no redirect-follow. Registry completeness is checked by `apps/egress/src/ssrfRegistry.test.ts` against a dated IANA snapshot.
2. **Subnet NSG** — `snet-egress` only (`egressNsgEnforce`: `off`, `deny-list-only`, or `enforce`; default `deny-list-only`). Rules load from `infra/azure/nsg-egress-rules.json`.
3. **Azure Firewall (optional)** — when `deployFirewall` is true: per-subnet platform lists, `egressFqdnMode` (`any` or `allowlist`), `threatIntelMode` (default `Deny`). Stronger than the NSG alone; costs ~$900/mo.
4. **Network probe** — scheduled/demand Container Apps Job running `apps/egress/src/netprobe.ts`; evidence lands in the egress workspace as `egress.netprobe_check` / `egress.netprobe_result` (summary includes `denyProven` and `closingDenyProven`). A green `ok` proves scored checks matched; NSG deny rows are proven only when `denyProven` is true (`blob-pe-443` with pinned endpoint addresses). On unpinned installs the scheduled job stays `ok: true` with `denyProven: false`; `just infra net-verify` exits 3. The closing deny is proven only with `netprobeClosingDenyTarget` and the firewall off. Read declared posture from the `netControls` deployment output (`probe.denyProvable`) next to the last probe result (`just infra net-verify`). **Unverified in Azure** until recorded in the probe table below.

Layers 1–2 apply to every install. Layer 3 applies only when the firewall is deployed. Layer 4 is on by default (`deployNetprobe`).

### What the old text means now

The **primary control** wording in the Challenge outcome (line 43) and the Deployment note (lines 66–77) describes the **reference posture** with `deployFirewall=true` and, when used, `egressFqdnMode=allowlist`. It is not a claim about every live install. Present posture for an install is the `netControls` output plus the latest `egress.netprobe_result`, not prose in this file.

### The accepted-risk record

The block at lines 79–87 is unchanged. Those installs hold an exception of: firewall off, application filter on, NSG on once an operator has applied it (`egressNsgEnforce` not `off`), trusted single-tenant, with the probe result as the standing evidence. Update the operator's deployments-repo acceptance to point at `netControls` and the last successful `egress.netprobe_result` instead of restating posture here.

NSG rows still **unverified in Azure** until an operator records probe results below include: platform-flow allows (MCR, Front Door, Entra, Azure Monitor, load-balancer paths), whether `deny-cgnat` (`100.64.0.0/10`, enforce-only) breaks ingress, ILB backend ports for edge→egress, service-tag membership, and static private-endpoint addressing when `pinPrivateEndpointAddresses` is true.

### Host-node paths (documented Azure behavior)

There is no NSG deny row on `168.63.129.16` — Microsoft says not to explicitly deny that address on a Container Apps subnet ([Securing a Virtual Network in Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/firewall-integration)). Microsoft documents that traffic to `168.63.129.16` on ports 80/tcp and 32526/tcp is not subject to configured NSG rules. DNS to that address is not filtered unless the rule targets the `AzurePlatformDNS` service tag ([What is IP address 168.63.129.16?](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16)). Instance metadata at `169.254.169.254` is similarly exempt unless the `AzurePlatformIMDS` tag is used ([Network security groups overview — Azure platform considerations](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)). `ssrf.ts` is therefore the only control on `168.63.129.16` and on IMDS for proxied egress traffic. What a Container Apps replica actually sees at those addresses remains **unverified in Azure** until recorded in the probe table.

### New ranges

The filter now also blocks: `168.63.129.16/32`, IPv4 documentation `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, deprecated 6to4 relay `192.88.99.0/24`, IPv6 documentation `3fff::/20`, segment-routing `5f00::/16`, and embedded IPv4 in the IPv4-translated form `::ffff:0:0:0/96`, plus any additional non-forwardable range the IANA registry snapshot test requires (for example `100:0:0:1::/64` from RFC 9780). `EGRESS_EXTRA_BLOCKED_CIDRS` adds the install VNet prefix (and the template adds the Container Apps infrastructure slice) at boot.

### The honest limit

The NSG and firewall cannot protect Postgres or the Key Vault private endpoints egress legitimately uses (`kv-connections`, `kv-delegated`, and **kv-platform** for egress's own Key Vault references): the rule table must allow them. The egress identity holds Key Vault Secrets User on the whole kv-platform vault, so the network layer cannot stop an egress compromise from reading platform secrets; narrowing that grant (per-secret role assignments or a separate egress-only vault) is deferred in `TODO.md`. A bare HTTP request without an injected credential is still limited by the application filter; exfiltration with a stolen instruction is a separate trust-boundary problem (ADR-0013).

### Probe results

Fill this in on a real install after `just infra net-verify`. Until then every row is **not yet run on a real install**.

| Hypothesis | Source | Result | Date | Operator |
| --- | --- | --- | --- | --- |
| What does a replica see at `168.63.129.16` (ports 80, 32526, 53)? | `netprobe` wire-server checks (informational) | not yet run on a real install | | |
| What does a replica see at `169.254.169.254`? | `netprobe` IMDS check (informational) | not yet run on a real install | | |
| Can a populated Container Apps subnet accept an NSG as an update? | Operator rollout / Azure support | not yet run on a real install | | |
| Which platform flows the NSG must allow (MCR, Front Door, Entra, Monitor, ILB) | `nsg-egress-rules.json` rows marked hypothesis | not yet run on a real install | | |
| Does the `100.64.0.0/10` deny break ingress? | NSG row `deny-cgnat` (enforce mode only) | not yet run on a real install | | |
| Do edge and portal reach egress through the internal load balancer on 31080 and 31443 with the NSG on? | Inbound ILB backend ports (`allow-apps-subnet`) | not yet run on a real install | | |
| What source address does the NSG see for edge→egress traffic? | Inbound ILB rule hypothesis | not yet run on a real install | | |
| Are static private-endpoint addresses accepted when pinning is on? | `pinPrivateEndpointAddresses` + PE rows | not yet run on a real install | | |
| Does Basic firewall SKU support threat-intel `Deny`? | `threatIntelMode` (template uses Standard) | not yet run on a real install | | |
| Does a firewall application rule drop after the TCP handshake (TLS probe)? | `netprobe` public-host TLS checks | not yet run on a real install | | |
| Do firewall diagnostic table/column names match (`AZFWApplicationRule`, etc.)? | `firewall-diagnostics.bicep` alert | not yet run on a real install | | |
| Is an `AzurePlatformIMDS` service-tag deny safe on the Container Apps subnet (managed identity keeps working)? | Not in template — documented alternative to prefix deny | not yet run on a real install | | |
