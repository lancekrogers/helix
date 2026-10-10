# 0051. LLM admission control: install default budget, platform ceiling, in-flight caps

**Status:** Accepted _(recorded 2026-10-09)_
**Related:** ADR [0021](0021-metering-ledger.md) (metering ledger and block-new budgets), [0002](0002-postgres-role-split-rls.md) (platform spend definer and `inflight_leases` grants), [0011](0011-in-memory-rate-limiting.md) (Postgres counters, not Redis), [0028](0028-deployment-model-customer-deployed.md) (per-install settings), [0037](0037-platform-observability-otlp-boundary.md) (admission-denial metrics and spans), [0008](0008-llm-key-via-egress.md) (vendor key custody unchanged); `docs/features/llm-gateway.md`

## Context

Hosted apps are treated as possibly hostile. Before this work, three gaps let spend and concurrency
grow without a bound the operator could reason about:

- **Abandoned streams could meter $0.** When an app hung up, the edge aborted its side of the
  call, but egress could keep draining the vendor until completion while the ledger row waited for a
  final usage block that never arrived. The daily gate summed `costMicroUsd`, so those rows moved
  spend not at all. A hang-up **after** the upstream response headers arrived already tore the
  vendor connection down (characterization on loopback); the real leak was the **pre-header** window
  plus any cut stream that still wrote **$0**.
- **Approved apps with no `dollarsPerDay` were unlimited at the gateway**, even though approval
  baseline assumes $50/day (`BASELINE_DOLLARS_PER_DAY` in `packages/shared/src/approval.ts`).
- **Nothing capped total platform LLM spend or concurrent calls** across the three edge replicas:
  block-new per-app budgets could be satisfied in parallel by many in-flight calls, and there was no
  install-wide ceiling.

ADR-0021's block-new posture stays: an admitted call is never cut when the byte budget crosses;
only the next request is refused. This ADR records the admission-layer controls that sit in front
of that gate and the metering fixes that make abandoned and partial calls count.

## Decision

1. **Install default for an unset LLM budget.** When a manifest omits `dollarsPerDay`, the edge
   enforces `EDGE_LLM_DEFAULT_DOLLARS_PER_DAY` (default **50** USD/day, matching the approval
   baseline) for both the calendar day and the rolling burst window. The approval classifier still
   treats a *requested* unset cap as possibly unlimited (it cannot read the install knob). Setting
   the install knob to **`0`** makes unset unlimited again for installs that choose that.

2. **Platform-wide daily ceiling.** `EDGE_LLM_PLATFORM_DOLLARS_PER_DAY` refuses new LLM calls once
   the day's summed `costMicroUsd` across all apps reaches the ceiling (`503 capability_unavailable`,
   `retry-after` to local midnight).    Deployed installs get a Bicep default of `max(platformMonthlyUsdCap / 10,
   3 × EDGE_LLM_DEFAULT_DOLLARS_PER_DAY)` per day when the parameter is left at `-1`; **`0`**
   switches enforcement off. Spend is read through
   `platform_llm_spend_micro_usd`, a `SECURITY DEFINER` aggregate (ADR-0002) because `FORCE` RLS
   hides other apps' rows from `helix_edge`; the result is cached **five seconds** per replica.
   A failed read **fails closed** (`503`, `retry-after: 5`).

3. **In-flight caps as Postgres leases plus a per-replica semaphore.** Cross-replica limits use
   `inflight_leases` with advisory-locked, all-or-none acquire on scopes `llm:app:<appId>` and, for
   authenticated callers, `llm:user:<appId>:<userOid>` (`EDGE_LLM_MAX_APP_IN_FLIGHT` default 10,
   `EDGE_LLM_MAX_USER_IN_FLIGHT` default 3). Anonymous callers on `public` apps get the app scope
   only (per-IP rate limiting remains separate). `EDGE_LLM_MAX_IN_FLIGHT` (default **200**) is a
   per-replica in-process gate before the lease round trip — effective cluster concurrency is at most
   **cap × replica count**. **`0`** disables each knob. The lease is released only **after** the
   ledger row is written. An optional fetch-path cap reuses the same store on scope
   `fetch:app:<appId>` (`EDGE_FETCH_MAX_APP_IN_FLIGHT`, default off).

4. **Wall-clock call deadline.** `EDGE_LLM_MAX_CALL_MS` (default ten minutes) bounds each upstream
   LLM call via `AbortSignal` and sets lease TTL to the deadline plus a one-minute grace period.
   There is no off value: the deadline is always on. The edge→egress undici hop uses
   `maxCallMs + LLM_EGRESS_HOP_TIMEOUT_MARGIN_MS` so this abort wins before the fetch idle timeout;
   egress→vendor on `llm` instructions uses `EGRESS_LLM_TIMEOUT_MS` (derived from the same
   `llmMaxCallMs` in Bicep, default `maxCallMs + EGRESS_LLM_TIMEOUT_MARGIN_MS`), which must stay
   above the edge deadline. A hop timeout after dispatch is charged as a cut (`upstream_timeout`).

5. **Per-install settings under ADR-0028.** Every control above is an install parameter with the
   strict value as the default so a one-organization customer-deployed install may relax or disable
   individual knobs (`0` where noted; the deadline excepted).

6. **Refusal semantics.** Budget and platform-ceiling denials use existing HTTP shapes — no new
   shared error code. Per-app over-budget: `429 quota_exceeded` / burst `429 rate_limited`.
   Platform ceiling and concurrency limits: `503 capability_unavailable` with `retry-after: 1` for
   concurrency and seconds-to-midnight for the ceiling. Budget and ceiling refusals record
   throttled `quota_blocked` rows (20 per minute per app per replica) with `errorDetail` markers
   (`platform_ceiling` for the ceiling). Concurrency refusals write **no** ledger row; they increment
   `helix.gateway.admission_denied` and set span attributes only for concurrency reasons.

7. **Cut and failed calls are charged** (ADR-0021 amendment). Measured token counts are used when the
   stream delivered them; otherwise a byte estimate (`BYTES_PER_TOKEN = 3`) with `;usage=measured`,
   `;usage=estimated`, or `;usage=mixed` in `errorDetail`. Egress now passes an abort `signal` to the
   upstream request so a client hang-up closes the **pre-header** vendor window; ADR-0008 is
   unchanged — the vendor key still lives only in egress.

### Overshoot bound

Per app, block-new admits at most `appCap` concurrent calls; overshoot past `dollarsPerDay` is at
most **`appCap × worst-case call cost`**, where worst-case is the catalog context-window input
cost plus `outputTokenCapForEstimate(model, maxTokens) × output price` for the priciest allowed
model (a cut call uses the same caps on byte estimates). Platform-wide, overshoot is at most the
ceiling plus up to roughly **`appCap` calls per app** that read spend before a lease freed by a
still-settling row (the budget is read before acquire, not after the ledger write). The five-second
platform aggregate cache adds a similar lag on top. These are **bounds**, not exact gates.

## Consequences

- **Any tenant with an LLM grant can pull the shared platform ceiling as an availability lever**
  against every app on the install until local midnight. What bounds that today: new LLM grants and
  create-time capabilities require approval (not self-service baseline), cut-call byte estimates are
  capped at what a completed call could cost (context window plus output cap), and the Bicep-derived
  default ceiling is at least three times the per-app default. **Per-app fairness at the ceiling**
  (for example capping each app's contribution at its own daily budget) was considered and not built.
- **Reasoning tokens billed upstream but never streamed** are not estimated; a cut call may undercharge
  relative to the vendor invoice.
- **A rolling deploy, scale-in, or crash mid-stream** may strand a lease until TTL if the process
  exits before the handler's `finally` runs. Shutdown aborts in-flight LLM calls shortly before the
  hard drain deadline (`SHUTDOWN_ABORT_MARGIN_MS` before `SHUTDOWN_GRACE_MS`) so the cut path can
  write a ledger row and release the lease while shorter streams may still finish; SIGKILL or an
  overrun past the deadline can still strand rows for up to the lease TTL.
- **The dev gateway (`deployDevGateway`) is outside the platform ceiling.** Its LLM calls use
  `env=dev`, which `platform_llm_spend_micro_usd` does not sum. Enabling the dev gateway is a
  precondition that operators accept unbounded platform-wide dev spend unless they add separate
  controls.
- **Byte estimates can be tens of percent off**; every starting cap and TTL is a guess until real
  traffic exists (defaults: $50/day install baseline, platform ceiling at least three times that
  when derived from Bicep defaults,
  200 per-replica sockets, 10-minute deadline, fetch lease TTL ten minutes when enabled).
- **The fetch cap counts a call for at most its TTL**; release on `reply.raw` `close` can race a
  socket already gone — the slot is held until TTL (documented in `docs/features/fetch-proxy.md`).
- **Platform `retry-after` assumes the edge and database share a time zone** for `date_trunc('day',
  now())`.
- **Already-approved apps pick up new defaults on deploy** — see operator rollout notes in
  `apps/docs/src/deploy/updates.md`.
- **Loopback tests prove abort, charging, leases, and ceiling behavior locally.** Abort through
  Container Apps ingress between edge and egress is **unverified in Azure**.

## Considered and rejected

- **Reserve worst-case cost at admission.** Turns block-new into block-if-it-might-exceed — a
  substantive ADR-0021 change — and with `maxTokens` up to 128,000 would block most requests near
  the cap.
- **Dedicated accumulator table for platform spend.** A second source of truth that can drift; the
  edge would need `UPDATE`, letting a compromised edge reset the ceiling. A shared `rate_counters`
  row overflows its `INTEGER` count at about **$2,147** of micro-USD.
- **Portal pushes a ceiling flag through the registry projection.** Polling loop and stale data for
  a number the gateway should own.
- **Alert-only platform spend.** Ruled out given the possibly-hostile audience: alerts do not stop
  an in-flight drain.
- **Per-process semaphore as the only cap.** Limit becomes **cap × replicas** — the failure mode
  ADR-0011 documents for rate limits.
- **Require a number at LLM approval time.** Portal change plus backfill; the edge would still need
  the install fallback.
- **Leave unset `dollarsPerDay` unbounded and document it.** Rejected: approved apps silently
  unlimited.
- **Counted tokens only on cut streams.** A hang-up before `message_start` still paid nothing at the
  vendor while egress could finish the call.
- **Pre-charge with a settling second row.** Two rows per call and orphan recovery; the only option
  that also covers an edge crash — revisit if that residual matters.
