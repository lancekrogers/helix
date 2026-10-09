import {
  metrics,
  SpanKind,
  SpanStatusCode,
  trace,
  type Attributes,
  type Counter,
  type Histogram,
  type MeterProvider,
  type ObservableGauge,
  type Span,
  type Tracer,
} from "@opentelemetry/api";
import {
  DURATION_BUCKETS_MS,
  INSTR_APP_VISITS,
  INSTR_GATEWAY_ADMISSION_DENIED,
  INSTR_GATEWAY_CUT_CHARGES,
  INSTR_GATEWAY_PLATFORM_SPEND_RATIO,
  INSTR_GATEWAY_CALLS,
  INSTR_GATEWAY_DURATION,
  INSTR_REGISTRY_LOAD_FAILURES,
  INSTR_REGISTRY_STALE_FOR_MS,
  INSTR_SESSION_GATE_DENIED,
  INSTR_TRUST_PROXY_UNRESOLVED,
} from "@azx-pbc/shared/telemetry";
import { SERVICE_NAME } from "./serviceName.js";
import type { FastifyReply, FastifyRequest } from "fastify";

/**
 * The edge's tracer and instruments.
 *
 * **This module imports `@opentelemetry/api` and nothing else** — the facade is
 * dependency-free and no-ops when no provider is registered, which is what lets
 * it be reached from inside `buildApp()` without dragging an SDK or an exporter
 * into the test path (ADR-0037 decision 3). The SDK lives in
 * `@azx-pbc/telemetry`, imported only by `server.ts`.
 */

/**
 * Safe at module scope, unlike {@link instruments} below: `trace.getTracer()`
 * hands back a `ProxyTracer` that re-resolves its delegate on **every**
 * `startSpan`, so a tracer captured before `startTelemetry()` runs still emits
 * once a provider is registered.
 */
export const tracer: Tracer = trace.getTracer(SERVICE_NAME);

/** Every metric the edge writes. One object so a call site can't miss one. */
export interface EdgeInstruments {
  /** `capability`, `outcome`, `appId`. */
  gatewayCalls: Counter;
  /** `capability`, `outcome` — no `appId`, per ADR-0037 decision 8's table. */
  gatewayDuration: Histogram;
  /** `outcome` ∈ `REGISTRY_LOAD_OUTCOMES`. */
  registryLoadFailures: Counter;
  /**
   * Observable, and deliberately so: ADR-0025's age rule exists to catch
   * "loads stopped being *attempted* at all", and a synchronous gauge recorded
   * at each load attempt reports nothing in exactly that fault. The callback is
   * attached by whoever holds the freshness reader.
   */
  registryStaleForMs: ObservableGauge;
  /** `reason` ∈ `SESSION_DENIAL_REASONS`. */
  sessionGateDenied: Counter;
  /**
   * Observable, like {@link registryStaleForMs}: 1 while the trust-proxy
   * check is degraded (the forwarded walk never resolved on the last N
   * proxied requests), 0 while verified healthy, and **absent below N** — a
   * gauge reading 0 on an unmeasured state would claim health nobody has
   * seen. Attached by `wireTrustProxyHealth` (`routing/trustProxyHealth.ts`).
   */
  trustProxyUnresolved: ObservableGauge;
  /** `appId`, `outcome` ∈ `VISIT_RECORD_OUTCOMES` (ADR-0050). */
  appVisits: Counter;
  /** `appId`, `basis` ∈ `CUT_CHARGE_BASES` — operational only, never reconciled with the ledger. */
  gatewayCutCharges: Counter;
  /**
   * `capability`, `reason` ∈ `ADMISSION_DENIAL_REASONS`, `appId`. Never `userOid`.
   * Not gated by the denial throttle — counts refusals the ledger drops.
   */
  gatewayAdmissionDenied: Counter;
  /** Cached platform spend over the configured ceiling; dimension `helix.env`. */
  platformSpendRatio: ObservableGauge;
}

/**
 * The last provider {@link instruments} built against, and what it built.
 *
 * **Not a plain module-level singleton, and this is the whole point of the
 * function.** `metrics.getMeter()` has no proxy — it calls
 * `getMeterProvider().getMeter()` immediately, and with nothing registered that
 * is `NOOP_METER_PROVIDER`, which returns a permanently-inert meter. ES imports
 * are hoisted, so `server.ts`'s `import { buildApp } from "./app.js"` evaluates
 * this whole module graph *before* the `startTelemetry(SERVICE_NAME)` call on
 * the next line executes. A `const meter = metrics.getMeter(…)` at module scope
 * would therefore bind to the noop provider and **every metric would silently
 * vanish in production while every test passed** — the tests register their own
 * provider first, so they would never see it.
 *
 * Keying the cache on provider identity makes the ordering irrelevant: the
 * first call after a provider is registered rebuilds against it, and a test
 * that swaps providers gets fresh instruments without a reset hook.
 */
let builtAgainst: MeterProvider | null = null;
let cached: EdgeInstruments | null = null;

export function instruments(): EdgeInstruments {
  const provider = metrics.getMeterProvider();
  if (cached && builtAgainst === provider) return cached;

  const meter = provider.getMeter(SERVICE_NAME);
  builtAgainst = provider;
  cached = {
    gatewayCalls: meter.createCounter(INSTR_GATEWAY_CALLS, {
      description: "Gateway calls by capability and outcome. Operational only — never billing.",
    }),
    gatewayDuration: meter.createHistogram(INSTR_GATEWAY_DURATION, {
      description: "Gateway call duration, measured to stream close.",
      unit: "ms",
      // OTel's default buckets top out at 10s and an LLM stream runs longer.
      advice: { explicitBucketBoundaries: [...DURATION_BUCKETS_MS] },
    }),
    registryLoadFailures: meter.createCounter(INSTR_REGISTRY_LOAD_FAILURES, {
      description: "Registry projection load failures since boot.",
    }),
    registryStaleForMs: meter.createObservableGauge(INSTR_REGISTRY_STALE_FOR_MS, {
      description: "Age of the served registry projection. Absent until the first load succeeds.",
      unit: "ms",
    }),
    sessionGateDenied: meter.createCounter(INSTR_SESSION_GATE_DENIED, {
      description: "App-host session-gate denials by reason.",
    }),
    trustProxyUnresolved: meter.createObservableGauge(INSTR_TRUST_PROXY_UNRESOLVED, {
      description:
        "1 when the last N proxied requests never resolved a forwarded client IP " +
        "(trust-proxy /health check degraded); 0 when verified healthy; absent below N.",
    }),
    appVisits: meter.createCounter(INSTR_APP_VISITS, {
      description:
        "Hosted-app document loads the edge tried to record, by outcome. Operational only — " +
        "the owner-facing counts come from app_visits.",
    }),
    gatewayCutCharges: meter.createCounter(INSTR_GATEWAY_CUT_CHARGES, {
      description:
        "LLM calls charged without a final usage block, by how the charge was derived. Operational only; never reconciled with the ledger.",
    }),
    gatewayAdmissionDenied: meter.createCounter(INSTR_GATEWAY_ADMISSION_DENIED, {
      description: "LLM gateway admission denials by capability and reason.",
    }),
    platformSpendRatio: meter.createObservableGauge(INSTR_GATEWAY_PLATFORM_SPEND_RATIO, {
      description:
        "Cached platform LLM spend today divided by the configured daily ceiling. Absent until the first successful read.",
    }),
  };
  return cached;
}

/**
 * Record a thrown value on a span and mark it failed.
 *
 * The message reaches the span, which is a retained backend — acceptable here
 * and nowhere near egress, whose error text can embed credential material
 * (`apps/egress/src/proxy.ts`'s deliberately empty `catch`). Edge errors are our
 * own.
 */
function failSpan(span: Span, err: unknown): void {
  span.recordException(err instanceof Error ? err : new Error(String(err)));
  span.setStatus({ code: SpanStatusCode.ERROR });
}

/**
 * Run a handler inside a fresh **root** server span, ended when the handler
 * settles.
 *
 * `root: true` is ADR-0037 decision 7 belt-and-braces: the inject-only
 * propagator already makes an inbound `traceparent` unextractable, and this
 * makes the span parentless even if something did put one in the active
 * context. Every request into the edge originates from untrusted app code, so a
 * platform trace must never be graftable from outside.
 *
 * **The span ends at stream close, which is what ADR-0037 decision 5 requires**
 * — and it does so for both streaming shapes in this codebase, which is worth
 * stating because the obvious reading of that decision says otherwise:
 *
 *  - `gateway/llm.ts` drives its own `for await` over the upstream events, so
 *    its promise plainly does not settle until the last byte is written;
 *  - `gateway/fetch.ts` and `apps/egress/src/proxy.ts` end with
 *    `return reply.send(stream)`, which *looks* like it resolves as soon as the
 *    pipe is wired. It does not: Fastify's `Reply` is thenable, and awaiting it
 *    resolves when the response finishes. Measured against Fastify 5.12.0 — a
 *    ~90 ms body yields a ~98 ms awaited handler and a thenable that settles at
 *    the same instant `reply.raw` emits `close`.
 *
 * So one helper covers both, and `apps/edge/src/spans.test.ts` pins the
 * property with a deliberately slow body. That test is the guard: if a future
 * Fastify makes `send` resolve early, every streamed span collapses to ~0 ms —
 * which the ADR rightly calls worse than no metric, because it looks like data.
 */
export function withRootSpan<T>(
  name: string,
  attributes: Attributes,
  fn: (span: Span) => Promise<T>,
  options: { reply?: FastifyReply } = {},
): Promise<T> {
  return tracer.startActiveSpan(
    name,
    { root: true, kind: SpanKind.SERVER, attributes },
    async (span) => {
      try {
        return await fn(span);
      } catch (err) {
        failSpan(span, err);
        throw err;
      } finally {
        gradeFromResponse(span, options.reply);
        span.end();
      }
    },
  );
}

/**
 * Mark a span failed when the response says so, not only when the handler threw.
 *
 * Every HTTP call site must pass `reply`, because **this codebase signals
 * failure by returning normally.** `gateway/fetch.ts` catches its error, meters
 * it, and calls `sendFetchError(reply, 502, …)`; the app-data verbs do the same
 * through `sendApiError`. A span graded only from a `catch` therefore records
 * every 502 as a success, and a backend's built-in error view — which keys on
 * span status, not on our custom `helix.outcome` attribute — shows a clean
 * trace for the requests an operator most wants to find.
 *
 * **5xx only. A 4xx stays UNSET, deliberately**: a 401 from the session gate or
 * a 403 from the manifest allowlist is the platform working exactly as
 * designed, and marking those ERROR would bury real faults under the ordinary
 * background of a public endpoint refusing things.
 *
 * Only ever *raises* to ERROR — a span already failed in the `catch` keeps that
 * status even when no response was written.
 */
function gradeFromResponse(span: Span, reply: FastifyReply | undefined): void {
  if (reply && reply.statusCode >= 500) span.setStatus({ code: SpanStatusCode.ERROR });
}

/**
 * Wrap a route handler in a root span, preserving its arity.
 *
 * The app-host handlers take a trailing `slug`; the auth-host ones do not.
 * Wrapping generically keeps the three credential-bearing routes
 * (`/_auth/complete`, the OIDC start and its callback) from each growing their
 * own copy of the attribute set — which is exactly the drift ADR-0037's
 * consequences call "the most likely way the decision decays."
 *
 * `attributes` is a function of the request so a caller can reach
 * `spanUrlAttributes(req.url)` without the wrapper knowing about URLs.
 */
export function spanRoute<A extends unknown[]>(
  name: string,
  attributes: (req: FastifyRequest) => Attributes,
  handler: (req: FastifyRequest, reply: FastifyReply, ...rest: A) => Promise<void>,
): (req: FastifyRequest, reply: FastifyReply, ...rest: A) => Promise<void> {
  return (req, reply, ...rest) =>
    withRootSpan(name, attributes(req), () => handler(req, reply, ...rest), { reply });
}
