import { randomUUID } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import {
  type FetchErrorCode,
  OUTCOME_HEADER,
  parseFetchTarget,
  REQUEST_HEADER_SAFELIST,
  RESPONSE_HEADER_BLOCKLIST,
} from "@azx-pbc/shared";
import { capBody } from "@azx-pbc/shared/bodyCap";
import type { GatewayConfig } from "../config.js";
import type { RegistryReader } from "../registry/projection.js";
import { meterIdentity, type CallerResolver } from "../auth/gate.js";
import { resolveServingEntry } from "../auth/routes/appHost.js";
import type { OriginCheck } from "../auth/validate.js";
import { anonRateLimited, type IpRateLimiter } from "./ipRateLimiter.js";
import type { DenialThrottle } from "./denialThrottle.js";
import { EgressProviderError, type EgressProvider } from "./egressProvider.js";
import { mintInstruction } from "./instruction.js";
import { trace } from "@opentelemetry/api";
import { spanUrlAttributes } from "@azx-pbc/shared/logging";
import {
  ATTR_APP_SLUG,
  ATTR_CAPABILITY,
  ATTR_CONNECTION,
  ATTR_METHOD,
  ATTR_PROVIDER_REF,
  ATTR_REASON,
  ATTR_TARGET_ORIGIN,
  ATTR_TARGET_PATH,
  ROUTE_FETCH,
  SPAN_FETCH,
} from "@azx-pbc/shared/telemetry";
import { withRootSpan } from "../telemetry.js";
import {
  errorDetailOf,
  fetchPathOf,
  meterAdmissionDenied,
  meterGatewayCall,
  type GatewayOutcome,
  type UsageStore,
} from "./usage.js";
import type { AcquireResult, LeaseStore } from "./leaseStore.js";

/**
 * `/_api/fetch/<url>` — the fetch-proxy policy plane (fetch-proxy design §7).
 * The edge authorizes (gate, CSRF, manifest allowlist, per-app budget), mints a
 * signed attested instruction, and forwards the call to `helix-egress` — which
 * holds the secrets and the internet route the edge deliberately lacks. The
 * upstream response streams straight back. Every call is metered into
 * `gateway_calls` (capability `fetch`, model = target origin, plus the request
 * `path` and `method`) — including the allowlist denial, which is recorded as
 * `forbidden` and is the one outcome here that never reaches egress. The
 * target's query string is never persisted (that is where credentials are
 * conventionally placed) — but the path is, and a path can carry a secret too:
 * see `fetchPathOf` in `usage.ts` for why no heuristic tries to spot one.
 */

export interface FetchGatewayRuntime {
  config: GatewayConfig;
  registry: RegistryReader;
  resolveCaller: CallerResolver;
  /** CSRF seam (dev-mode §5.4): edge = exact same-origin; dev-gateway = allowlist. */
  checkOrigin: OriginCheck;
  anonLimiter: IpRateLimiter | null;
  /** Caps metered allowlist denials per (app, env). null ⇒ uncapped (tests). */
  denialThrottle: DenialThrottle | null;
  /** null ⇒ EDGE_EGRESS_URL unset; the capability 503s. */
  egress: EgressProvider | null;
  usage: UsageStore | null;
  /** null ⇒ HELIX_INSTRUCTION_SECRET unset; the capability 503s. */
  instructionKey: Buffer | null;
  /** Per-app in-flight cap via leases; null (or maxAppInFlight 0) disables it. */
  concurrency: { leases: LeaseStore; maxAppInFlight: number } | null;
}

const REQUEST_SAFE = new Set(REQUEST_HEADER_SAFELIST);
const RESPONSE_BLOCKED = new Set([...RESPONSE_HEADER_BLOCKLIST, OUTCOME_HEADER, "content-length"]);
const BODYLESS = new Set(["GET", "HEAD"]);

/** Fetch has no wall-clock deadline; idle timeouts bound calls. TTL is the backstop. */
const FETCH_LEASE_TTL_MS = 10 * 60_000;

function sendFetchError(
  reply: FastifyReply,
  status: number,
  code: FetchErrorCode,
  message: string,
): void {
  reply
    .status(status)
    .header("cache-control", "no-store")
    .type("application/json; charset=utf-8")
    .send({ code, message });
}

function safeRequestHeaders(headers: FastifyRequest["headers"]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (REQUEST_SAFE.has(k) && typeof v === "string") out[k] = v;
  }
  return out;
}

/**
 * Map the egress outcome label to a ledger outcome — the ledger's outcome
 * granularity, restated at the consumer. `connection_required` is its own
 * label: "the caller has no usable connection" is a consent state, not a
 * policy refusal, and the ledger separates
 * the two. The provider-shaped codes (`provider_unavailable`,
 * `provider_misconfigured`) ledger as `refusal`, like egress's other 4xx
 * refusals. Everything else — a vendor throttle, a temporary renewal failure,
 * any future word — folds to `error`, so an unknown label can never masquerade
 * as a clean `ok`.
 */
function toOutcome(egressOutcome: string): GatewayOutcome {
  if (egressOutcome === "ok") return "ok";
  if (egressOutcome === "connection_required") return "connection_required";
  if (
    egressOutcome === "refusal" ||
    egressOutcome === "provider_unavailable" ||
    egressOutcome === "provider_misconfigured"
  ) {
    return "refusal";
  }
  return "error";
}

export function makeFetchHandler(rt: FetchGatewayRuntime) {
  async function handleFetch(
    req: FastifyRequest,
    reply: FastifyReply,
    slug: string,
  ): Promise<void> {
    const entry = resolveServingEntry(rt.registry, slug, reply);
    if (!entry) return;

    const caller = await rt.resolveCaller(req, reply, entry);
    if (!caller) return;
    const identity = meterIdentity(caller);
    // Kept as its own binding on purpose: `userOid` alone crosses the egress
    // trust boundary below, and the captured labels must not follow it there —
    // AttestedInstructionSchema is deliberately the opaque id and nothing more.
    // `userKind` joins it only on a delegated mint, where egress needs the
    // recorded kind to refuse anon/password callers; the
    // display half (`userName`/`userEmail`) still never crosses.
    const { userOid, userKind } = identity;

    if (await anonRateLimited(rt.anonLimiter, req, entry, caller)) {
      sendFetchError(reply, 429, "rate_limited", "per-IP request budget exhausted");
      return;
    }

    // CSRF: the proxy call is same-origin by construction; reject anything else.
    if (!rt.checkOrigin(req, entry)) {
      sendFetchError(reply, 403, "forbidden", "Origin not allowed");
      return;
    }

    if (!rt.egress || !rt.usage || !rt.instructionKey) {
      sendFetchError(reply, 503, "upstream_error", "fetch capability is not configured");
      return;
    }
    // Bound once, above the allowlist denial — both it and the quota gate below
    // meter through this, and the 503 guard has already narrowed it.
    const usage = rt.usage;

    const target = parseFetchTarget(req.raw.url ?? "");
    if (!target) {
      sendFetchError(reply, 400, "bad_target", "missing or invalid target URL");
      return;
    }

    // Authz: the target origin must be a proxied origin in this app's manifest.
    // The lookup is on the canonical origin, so percent-encoding can't bypass it.
    if (!entry.fetch.connections.has(target.origin)) {
      // Meter the denial — an app reaching for an origin its manifest never
      // granted is the most audit-interesting event on this surface, and it used
      // to leave no trace at all: the request log kept it for 30 days and the
      // ledger, which is what the Audit page reads, knew nothing.
      //
      // Capped per (app, env). This is the one write on the handler that no
      // other gate bounds — the per-IP limiter skips authenticated callers, this
      // check returns before the daily budget, and `fetchRequestsToday` excludes
      // `forbidden` — so without the throttle a retry loop against a typo'd host
      // appends to an undeletable table at line rate. The first N per window
      // carry the whole audit signal ("this app reached for an origin it doesn't
      // have"); the rest are dropped with a magnitude summary on the log.
      const decision = rt.denialThrottle
        ? await rt.denialThrottle.admit(entry.appId, caller.env)
        : { meter: true as const, suppressedAt: undefined };
      if (decision.suppressedAt !== undefined) {
        req.log.warn(
          {
            appId: entry.appId,
            env: caller.env,
            origin: target.origin,
            attempts: decision.suppressedAt,
          },
          "allowlist-denial metering suppressed — this app is over its denial budget for the window",
        );
      }
      // The metric is NOT gated on `decision.meter`, and that divergence is
      // deliberate. The throttle is a write-amplification defence on an
      // append-only table with no DELETE grant — it exists to stop an app
      // filling the ledger, not to hide the event. "An app is hammering an
      // origin it was never granted" is precisely what an operator wants to
      // see, and past N the ledger is blind to it by design.
      //
      // This makes `helix.gateway.calls` and `gateway_calls` provably differ,
      // which strengthens ADR-0037 decision 9 rather than bending it: the two
      // can now never be reconciled, so nobody will try.
      meterGatewayCall({
        appId: entry.appId,
        capability: "fetch",
        outcome: "forbidden",
      });
      if (decision.meter) {
        // Deliberately not awaited: `record` opens a transaction
        // (`withPartition`) held across four round-trips on the pool that also
        // serves the budget checks. The 403 must not wait on that, and the
        // throttle above is what bounds how many can be in flight.
        void usage
          .record({
            appId: entry.appId,
            env: caller.env,
            ...identity,
            capability: "fetch",
            model: target.origin,
            inputTokens: 0,
            outputTokens: 0,
            outcome: "forbidden",
            statusCode: 403,
            path: fetchPathOf(target.pathname),
            method: req.method,
            errorDetail: `origin ${target.origin} is not a proxied origin`,
          })
          .catch((err: unknown) => req.log.warn({ err }, "gateway usage record failed"));
      }
      sendFetchError(reply, 403, "forbidden", `origin ${target.origin} is not a proxied origin`);
      return;
    }
    // The origin is allowlisted; unwrap its credential source. Exactly one of
    // the three shapes mints a credential field: a secret-bound origin names
    // the stored secret, a provider-bound origin names the delegated provider
    // ref (the user's connection to that provider is what egress injects — the
    // edge holds no provider state and evaluates none), and a
    // keyless one carries neither. The union makes secret and provider
    // mutually exclusive, so the instruction's XOR holds by
    // construction.
    const credential = entry.fetch.connections.get(target.origin);
    const connection = credential?.kind === "secret" ? credential.connection : null;
    const provider = credential?.kind === "provider" ? credential.provider : null;

    // Recorded only now: the origin has been matched against the manifest
    // allowlist, so it is a value the operator granted rather than one the app
    // chose. `fetchPathOf` is the ledger's own cap — reusing it means the span
    // attribute and the `path` column cannot draw the line in different places.
    trace.getActiveSpan()?.setAttributes({
      [ATTR_TARGET_ORIGIN]: target.origin,
      [ATTR_TARGET_PATH]: fetchPathOf(target.pathname),
      ...(connection ? { [ATTR_CONNECTION]: connection } : {}),
      ...(provider ? { [ATTR_PROVIDER_REF]: provider } : {}),
    });

    // Quota (block-new): the per-app daily request budget from the manifest.
    const budget = entry.fetch.requestsPerDay;
    if (budget !== null) {
      const usedToday = await usage.fetchRequestsToday(entry.appId, caller.env);
      if (usedToday >= budget) {
        // No `durationMs`: refused before anything was dialled.
        meterGatewayCall({ appId: entry.appId, capability: "fetch", outcome: "quota_blocked" });
        await usage
          .record({
            appId: entry.appId,
            env: caller.env,
            ...identity,
            capability: "fetch",
            model: target.origin,
            inputTokens: 0,
            outputTokens: 0,
            outcome: "quota_blocked",
            statusCode: 429,
            path: fetchPathOf(target.pathname),
            method: req.method,
          })
          .catch((err: unknown) => req.log.warn({ err }, "gateway usage record failed"));
        sendFetchError(reply, 429, "rate_limited", "daily fetch budget exhausted");
        return;
      }
    }

    // Request body cap, fast-path: refuse a truthful oversized content-length
    // before minting an instruction or dialing egress. The byte counter on the
    // re-stream below is the real, framing-independent enforcement (issue #8).
    if (!BODYLESS.has(req.method)) {
      const declared = Number(req.headers["content-length"]);
      if (Number.isFinite(declared) && declared > rt.config.fetch.maxBodyBytes) {
        sendFetchError(reply, 413, "too_large", "request body exceeds the size cap");
        return;
      }
    }

    const conc = rt.concurrency;
    if (conc && conc.maxAppInFlight > 0) {
      let acquired: AcquireResult;
      try {
        acquired = await conc.leases.acquire(
          [{ scope: `fetch:app:${entry.appId}`, cap: conc.maxAppInFlight }],
          FETCH_LEASE_TTL_MS,
        );
      } catch (err) {
        req.log.warn({ err, event: "gateway.lease_unavailable" }, "lease acquire failed");
        sendFetchError(reply, 503, "upstream_error", "fetch concurrency check unavailable");
        return;
      }
      if (!acquired.ok) {
        meterAdmissionDenied({
          appId: entry.appId,
          capability: "fetch",
          reason: "concurrency_app",
        });
        trace.getActiveSpan()?.setAttribute(ATTR_REASON, "concurrency_app");
        sendFetchError(reply, 429, "rate_limited", "too many concurrent requests for this app");
        return;
      }
      let released = false;
      const releaseLease = (): void => {
        if (released) return;
        released = true;
        void conc.leases
          .release(acquired.leaseId)
          .catch((err: unknown) =>
            req.log.warn({ err, event: "gateway.lease_release_failed" }, "lease release failed"),
          );
      };
      // 'close' fires after the response finishes and after a hang-up: the right moment
      // to free the slot. A finally block would free it at the headers, because the
      // streamed body outlives this function's return.
      reply.raw.once("close", releaseLease);
      if (reply.raw.destroyed && !reply.raw.writableEnded) releaseLease();
    }

    // Mint the attested instruction and forward to egress.
    const instruction = await mintInstruction(
      {
        appId: entry.appId,
        // The opaque id ONLY. The captured labels stop at the edge: egress is a
        // separate trust boundary and AttestedInstructionSchema deliberately
        // carries no display half.
        userOid,
        capability: "fetch",
        origin: target.origin,
        requestId: randomUUID(),
        env: caller.env,
        method: req.method,
        path: target.pathname,
        ...(connection ? { connection } : {}),
        // The delegated mint: the provider ref, never a
        // connection name — and the caller's principal kind is
        // mandatory on a delegated instruction, stamped from the session's
        // recorded kind (the dev gateway's dev identity yields `dev` the same
        // way, through `meterIdentity`). A kindless caller — a session
        // predating the kind column — is never fabricated into one: the
        // instruction mints without it and egress's strict verify refuses it,
        // which is the fail-closed answer for a kind the edge does not know.
        ...(provider ? { provider } : {}),
        ...(provider && userKind ? { userKind } : {}),
      },
      rt.instructionKey,
    );

    // Abort the egress call if the app goes away — but watch the *response*, not
    // the request. `req.raw` emits 'close' when the request body finishes
    // arriving (the ended stream auto-destroys), which for a proxy that drains
    // `req.raw` itself is normal completion, not a disconnect: watching it
    // aborted every POST/PUT/PATCH/DELETE the moment its body landed, long
    // before egress answered. The ServerResponse's 'close' fires when the
    // connection actually goes away, and `writableEnded` separates "we
    // finished answering" from "they hung up". Fastify's own `request.signal` is
    // wired to the same unguarded `req.on('close')` — do not substitute it.
    //
    // `writableEnded`, not `writableFinished`: the two agree on a real socket,
    // but light-my-request's null socket never settles `writableFinished`, so
    // under `app.inject()` every ordinary response would look like a hang-up.
    const abort = new AbortController();
    reply.raw.on("close", () => {
      if (!reply.raw.writableEnded) abort.abort();
    });

    // Count the request bytes forwarded to egress: a chunked / CL-absent /
    // lying-CL upload can't stream past the cap uncounted. A trip destroys
    // req.raw and errors the forward → the catch maps it to a 413.
    let requestCapTripped = false;
    const requestBody = BODYLESS.has(req.method)
      ? null
      : capBody(req.raw, rt.config.fetch.maxBodyBytes, "request", () => {
          requestCapTripped = true;
        });

    const startedAt = performance.now();
    const record = (
      outcome: GatewayOutcome,
      extra: { statusCode?: number; errorDetail?: string } = {},
    ): Promise<void> => {
      const durationMs = Math.round(performance.now() - startedAt);
      meterGatewayCall({ appId: entry.appId, capability: "fetch", outcome, durationMs });
      return usage
        .record({
          appId: entry.appId,
          env: caller.env,
          ...identity,
          capability: "fetch",
          model: target.origin,
          inputTokens: 0,
          outputTokens: 0,
          outcome,
          durationMs,
          statusCode: extra.statusCode ?? null,
          errorDetail: extra.errorDetail ?? null,
          // `pathname` only — the query is dropped and the value is capped. See
          // `fetchPathOf`; the same line is drawn by the log serializer.
          path: fetchPathOf(target.pathname),
          method: req.method,
        })
        .catch((err: unknown) =>
          req.log.warn(
            {
              err,
              event: "gateway.usage_record_failed",
              appId: entry.appId,
              capability: "fetch",
              outcome,
            },
            "gateway usage record failed",
          ),
        );
    };

    try {
      const res = await rt.egress.proxy({
        instruction,
        target: target.href,
        method: req.method,
        headers: safeRequestHeaders(req.headers),
        body: requestBody,
        signal: abort.signal,
        correlationId: String(req.id),
      });

      await record(toOutcome(res.outcome), { statusCode: res.status });

      reply.status(res.status).header("cache-control", "no-store");
      for (const [k, v] of Object.entries(res.headers)) {
        if (!RESPONSE_BLOCKED.has(k) && v !== undefined) reply.header(k, v);
      }
      // Count the response bytes on the way to the app: egress already caps, but
      // the edge caps independently (defense-in-depth — the two hops don't trust
      // each other). Status + headers are committed, so a trip truncates the
      // body rather than erroring (issue #8).
      return reply.send(
        capBody(res.body, rt.config.fetch.maxBodyBytes, "response", () => {
          req.log.warn(
            { appId: entry.appId, origin: target.origin, limit: rt.config.fetch.maxBodyBytes },
            "fetch response body exceeded the size cap — truncated",
          );
        }),
      );
    } catch (err) {
      // A request-body cap trip surfaces here as a failed egress forward; report
      // it as a 413 rather than a generic upstream error (nothing sent yet).
      if (requestCapTripped) {
        await record("refusal", { statusCode: 413 });
        sendFetchError(reply, 413, "too_large", "request body exceeds the size cap");
        return;
      }
      await record("error", { errorDetail: errorDetailOf(err) });
      if (err instanceof EgressProviderError) {
        sendFetchError(reply, 502, "upstream_error", "egress request failed");
        return;
      }
      sendFetchError(reply, 502, "upstream_error", "fetch failed");
    }
  }

  /**
   * The one gateway route whose URL is attacker-controlled: `/_api/fetch/<target>`
   * splices the app's chosen target in unencoded, so *its* query string becomes
   * ours — and that is conventionally where an API key or an Azure SAS `sig`
   * lives (ADR-0037 decision 6). `spanUrlAttributes` runs `redactUrl` and then
   * drops the query wholesale, so no parameter-name list has to be right.
   *
   * Per-target attributes are added inside the handler, once the target has been
   * parsed and matched against the manifest allowlist — an origin that failed
   * that check is not a value worth recording under a stable key.
   */
  return (req: FastifyRequest, reply: FastifyReply, slug: string): Promise<void> =>
    withRootSpan(
      SPAN_FETCH,
      {
        [ATTR_CAPABILITY]: "fetch",
        [ATTR_APP_SLUG]: slug,
        [ATTR_METHOD]: req.method,
        "http.route": ROUTE_FETCH,
        ...spanUrlAttributes(req.url),
      },
      () => handleFetch(req, reply, slug),
      { reply },
    );
}
