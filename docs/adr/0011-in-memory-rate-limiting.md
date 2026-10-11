# 0011. In-memory rate-limit / throttle state (single-replica)

**Status:** Superseded (2026-07-21) — the counters moved to a shared Postgres store; see Resolution below.
**Related:** `apps/edge/src/gateway/ipRateLimiter.ts`, `apps/edge/src/auth/loginThrottle.ts`, `apps/edge/src/gateway/counterStore.ts`; review ISSUE-07, ISSUE-15, issue #13

## Context

The edge needs a per-IP anonymous rate limiter and a per-(IP, app) password-login throttle. A shared store (Redis/DB) adds infrastructure and latency the pilot doesn't yet need.

## Decision

Keep rate-limit and login-throttle counters in per-process in-memory maps for v0, with periodic sweeping of expired buckets. This is documented as a deliberate single-replica scope.

## Consequences

- Simple, fast, no extra infrastructure.
- **Per-process state does not hold across replicas**: with N edge instances the effective limit is N × the configured limit — a real weakening of the login throttle, which (with ADR [0004](0004-auth-model.md)'s scrypt cost) is the economic defense for shared-password apps.
- In-memory maps must be swept or they grow unbounded.

## Open question / required hardening

- `loginThrottle.sweep()` is currently **never scheduled** → unbounded map growth (ISSUE-07). Wire it on an interval like `anonRateLimiter`.
- Check-then-increment is non-atomic (TOCTOU); concurrent attempts multiply the budget (ISSUE-15).
- Move to a shared atomic counter (DB `UPDATE … RETURNING` / Redis) before the edge goes multi-replica.

## Review notes (2026-06-25)

The single-replica trade-off is acknowledged in-code; the un-scheduled sweep and TOCTOU are concrete bugs on top of the documented scope.

## Challenge outcome (2026-06-26)

WEAKEN → **premise falsified** (filed **#13**). The "single-replica scope" is contradicted by the shipped infra: `infra/azure/modules/containerapp.bicep:40,43` set `minReplicas=1, maxReplicas=3` and the edge inherits it (no override in `main.bicep`), so the N× / uncoordinated throttle weakening this ADR warns about is **live in the M5 pilot**, not deferred. The unscheduled `loginThrottle.sweep()` and the check-then-increment TOCTOU above are confirmed in source. Newly noted: `trustProxy` is unset (`app.ts:112-116`), so `req.ip` behind the Container Apps Envoy may collapse to one bucket (or be XFF-spoofable if flipped on naively). **Before M5:** pin `maxReplicas=1` or land a shared atomic counter (a `gateway_calls`-style row — `helix_edge` already has INSERT); schedule the sweep; configure `trustProxy` correctly.

## Resolution (2026-07-21, issue #13)

Took the shared-atomic-counter branch — **not Redis**: adding a stateful service and a runtime/network dependency to the dependency-minimal trusted edge wasn't warranted for three small counters, and Postgres is already an edge dependency (the same reasoning ADR [0013](0013-egress-trust-model.md)'s resolution applies to the egress burn). Both counters now go through a `CounterStore` seam (`apps/edge/src/gateway/counterStore.ts`): `PgCounterStore` does one atomic `INSERT … ON CONFLICT DO UPDATE … RETURNING count` per admission against a `rate_counters` table (migration `20260721215912`, `helix_edge` full CRUD), keyed `anon:`/`login:` so the two limiters share one store without colliding. The in-flight lease store (ADR-0051) later made the same Postgres-with-no-Redis choice for the same reason.

This closes every item above: the limit **holds across replicas** (no more N×); the atomic upsert makes the login throttle **reserve-first**, closing the TOCTOU (ISSUE-15); one interval sweep in `server.ts` GCs both tables (fixes the never-scheduled sweep, ISSUE-07); and `EDGE_TRUST_PROXY` is now a config knob wired to Fastify `trustProxy` (default off). The in-memory maps survive only as `InMemoryCounterStore` for tests / single-process dev.

**Residual closed (2026-07).** The Container Apps ingress hop count has been verified against the live deployment and is set (`edgeTrustProxy` in `infra/azure`, applied to the edge and the dev-gateway), so `req.ip` resolves to the real client and per-client limits mean what they say. One qualification the closure should carry: the correct value is a property of a *deployment's* ingress topology, not of Helix. Under ADR [0028](0028-deployment-model-customer-deployed.md) each deployment applies its own IaC, so putting a CDN, WAF, or second proxy in front of the edge changes the hop count — too low and every client collapses into one bucket again, too high and `x-forwarded-for` becomes spoofable. Re-verify per deployment rather than treating this as settled platform-wide.

**Amended (2026-09) — the same decision, expressed as an address; the live verification does *not* carry over.** Upstream deleted the mechanism the paragraph above describes. Fastify 5.12.1 removed the hop-count form of `trustProxy` ([GHSA-3m5p-2c4r-xxw2](https://github.com/advisories/GHSA-3m5p-2c4r-xxw2)): trusting by hop position means the predicate structurally ignores the address it is handed, so anyone who reached the origin directly is "hop 0" and gets believed. `EDGE_TRUST_PROXY` now names the **address** of the trusted ingress — a CIDR/IP list or a proxy-addr preset — and `infra/azure` defaults it (`edgeTrustProxy: 'auto'`) to the address the ACA ingress actually presents. That default first shipped as `network.outputs.appsSubnetPrefix`, the apps subnet the edge itself runs in, which was wrong and is corrected below; it is `100.64.0.0/10` today.

This is not a new decision, and nothing downstream changed: `req.ip` is still the last address surviving a right-to-left walk of `[socket peer, ...x-forwarded-for]`, and behind a single ingress hop it resolves identically. What changed is that the predicate now validates the peer, which is strictly stronger than what it replaces. The per-deployment qualification above survives intact and applies to the new form for the same reason — a subnet is as much a property of a deployment's topology as a hop count was. `parseTrustProxy` (`apps/edge/src/config.ts`) **throws** on a bare integer rather than accepting it: fastify compiles a number to "trust nothing" silently, and every symptom of that is quiet — one bucket per app across the fleet, with `/health` green throughout.

**Residual closed (2026-09-03) — as a defect found, not a confirmation.** The 2026-07 closure above rested on a hop count checked against the live ingress. That check established that trusting exactly one hop yields the client; it did **not** establish that the ACA ingress peer's address falls inside `appsSubnetPrefix`, which is what the address form asserts. Measured against the live deployment, it does not, and never did: on a **workload-profile** Container Apps environment with `platformReservedCidr` unset, ACA draws ingress pod addresses from its [platform-reserved ranges](https://learn.microsoft.com/en-us/azure/container-apps/custom-virtual-networks) — `100.100.0.0/17`, `100.100.128.0/19`, `100.100.160.0/19`, `100.100.192.0/19`, in RFC 6598 shared address space. The apps subnet is where the *containers* get addresses, not the ingress that connects to them, so the shipped default trusted nothing.

The predicted silent failure was therefore real and live. Three failed `POST /_auth/login` from one client machine produced two `rate_counters` rows — `login:100.100.1.0:<appId>` and `login:100.100.0.147:<appId>` — one client bucketed **per Envoy pod**, neither key its address, `/health` green throughout. With `EDGE_TRUST_PROXY=100.64.0.0/10` the same traffic produced one row keyed on the real client. `X-Forwarded-For` carried the client address the whole time; only the CIDR the walk was told to trust was wrong. `main.bicep` now resolves `'auto'` to `100.64.0.0/10` — the whole RFC 6598 block rather than the four documented sub-ranges, because it covers anything Azure adds inside it later and the breadth is free: RFC 6598 space is not routable on the public internet, so no client can present such an address as a socket peer. **Do not reach for the VNet prefix or the `uniquelocal` preset** (`10/8` + `172.16/12` + `192.168/16` + `fc00::/7`) — an earlier version of this paragraph advised exactly that, and neither contains `100.100.x.x`: both look like a fix and change nothing.

Two things this does not close. `parseTrustProxy`'s boot-throw covers a hop count, not a wrong-but-well-formed CIDR — `10.0.2.0/23` was perfectly valid and perfectly useless — so the class of failure stays undetected by construction until the edge **self-reports** it (`TODO.md`: a `trust_proxy` sub-check on `/health` that reports whether the walk ever moved past the socket peer, not whether the configured value looks plausible). And the per-deployment qualification above survives intact — this makes it sharper: the correct value is a property of a *deployment's* ingress topology, and ACA's own topology was not what the template assumed. Re-verify per deployment (`infra/azure/README.md` deploy step 5 has the `rate_counters` read-back).

**Amended (2026-09-23) — the edge now self-reports the walk.** The residual above is closed by behaviour, not by config inspection. A `trust-proxy` sub-check on `/health` (`apps/edge/src/routing/trustProxyHealth.ts`) answers one question: **did `req.ip` ever differ from `req.socket.remoteAddress` on a request that carried `X-Forwarded-For`?** Deliberately not "is `req.ip` inside the configured CIDR" and not "is the value plausible" — both pass on exactly the failure that shipped, because the config is the very thing being graded. The measurement makes the failure loud within hours of a deploy instead of at the next manual re-check.

Four decisions, recorded because each was a real fork:

- **The denominator is forwarded requests only.** ACA probes, `containerapp exec` curls and local dev carry no `X-Forwarded-For`, and for them `req.ip === socket peer` is *correct*; counting them would degrade a quiet install for no reason. A request without the header never enters the measurement. (Corollary: a client that reaches the edge *directly* while sending the header counts as unresolved. On the deployed topology the container has no public address — the edge is only reachable through the ingress — so forwarded traffic that never resolves **is** the anomaly.)
- **Window, not latch.** The ring holds the last N forwarded samples, so the check can go bad again: a boot latch would cover a config mistake (a config change is a new revision and a new process) but stay green while Azure moved the ingress range under a running replica. Cumulative since-boot counters ride along in `metrics` for the operator; the graded condition is the window. Cost is O(1) per request — one counter and one ring write — because this sits on every request's hot path.
- **N = 50**, and it self-resolves: the availability tests probe `auth.<domain>/health` through the ingress from five regions every few minutes with the header attached, so a fresh replica fills its window on probes alone. Below N the check reads `ok` with "not enough proxied traffic yet (n/N)" — unmeasured, not healthy.
- **It alerts, via a gauge + rule** (the gap the TODO text did not see: a `degraded` `/health` alerted nobody — the availability tests fail only on `error`). The edge observes `helix.edge.trust_proxy.unresolved` (1 degraded, 0 verified healthy, **absent below N** — the same never-report-an-unmeasured-0 rule as the staleness gauge), and `alerts.bicep` carries a severity-2 metric rule next to the staleness rule. Grading it `error` instead would have bought alerting for free through the availability tests and was rejected: the platform still serves correctly — only per-IP fairness and throttling are gone — and an outage-grade page for a deploy-parameter mistake makes real outages harder to see.

The manual `rate_counters` re-check recipe in `infra/azure/README.md` is now the fallback, for confirming a degraded report or working without telemetry.
