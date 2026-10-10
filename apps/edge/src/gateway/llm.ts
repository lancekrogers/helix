import { randomUUID } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import {
  costUsd,
  estimateCutUsage,
  priceForModel,
  supportsStructuredOutputs,
  type ApiErrorCode,
  type LlmUsage,
} from "@azx-pbc/shared";
import { processShutdownSignal } from "@azx-pbc/shared/lifecycle";
import type { GatewayConfig } from "../config.js";
import type { RegistryReader } from "../registry/projection.js";
import { meterIdentity, type CallerResolver } from "../auth/gate.js";
import { resolveServingEntry } from "../auth/routes/appHost.js";
import type { OriginCheck } from "../auth/validate.js";
import { anonRateLimited, type IpRateLimiter } from "./ipRateLimiter.js";
import { LlmProviderError, type LlmProvider } from "./provider.js";
import { nativeCodec, type LlmWireCodec, type LlmWireContext } from "./llmCodec.js";
import {
  ERROR_DETAIL_MAX,
  errorDetailOf,
  meterAdmissionDenied,
  meterCutCharge,
  meterGatewayCall,
  type GatewayOutcome,
  type LlmSpend,
  type UsageStore,
} from "./usage.js";
import type { DenialThrottle } from "./denialThrottle.js";
import type { AcquireResult, LeaseRequest, LeaseStore } from "./leaseStore.js";
import { ReplicaGate } from "./replicaGate.js";
import { truncate } from "../auth/identity.js";
import { trace } from "@opentelemetry/api";
import {
  ATTR_APP_SLUG,
  ATTR_CAPABILITY,
  ATTR_CLIENT_DISCONNECTED,
  ATTR_REASON,
  ATTR_USAGE_BASIS,
  ROUTE_LLM,
  SPAN_LLM,
  type AdmissionDenialReason,
} from "@azx-pbc/shared/telemetry";
import { withRootSpan } from "../telemetry.js";

/**
 * `POST /_api/llm/chat` — the gateway's LLM capability (architecture §6.1,
 * project plan §4 M4). The choke point that makes per-app blast-radius real:
 * it authenticates the user (session gate), proves the request came from the
 * app's own origin (CSRF — §4.2), enforces the per-app model allowlist and
 * daily spend budget from the manifest or install default (§6.3), proxies to the
 * vendor through
 * the `LlmProvider` seam (the app never sees the key), and meters every call.
 *
 * Quota is **block-new, finish-in-flight**: the budget is checked once at
 * admission; an admitted request always runs to completion, even if it pushes
 * the app over budget — the next request is the one that gets blocked. An abort
 * by the client, or by the call deadline, is not a quota cut; the budget never
 * cuts an admitted call.
 *
 * The budget is denominated in **USD**, not tokens, so the cap means the same
 * thing across models (a token cap is a 10× range of dollars between haiku and
 * fable-5). Two windows are checked off the frozen `costMicroUsd` ledger column:
 * a calendar-day cap (the cost control — bounds the daily bill) and a rolling
 * 1-hour burst cap at a fraction of it (an availability control — a single
 * actor can't drain the whole day in one spike and lock the app out for 24h).
 */

/**
 * Rolling-hour burst cap = `dollarsPerDay × BURST_BUDGET_FRACTION`. With the
 * divisor at 6, draining the daily budget takes at least 6 hours. This is an
 * availability knob (it does not change the worst-case daily spend); retune
 * freely. The 1-hour window length itself lives in the SQL (usage.ts).
 */
const BURST_WINDOW_DIVISOR = 6;
const BURST_BUDGET_FRACTION = 1 / BURST_WINDOW_DIVISOR;

/** Lease TTL is the call deadline plus this, so a live call never loses its slot. */
const LEASE_GRACE_MS = 60_000;

/**
 * Ledger `errorDetail` for a call the app abandoned. `GatewayOutcome` has no
 * `cancelled` member and adding one would migrate an enum shared with the portal
 * and the DB, so the outcome stays `error` and this marker carries the meaning.
 */
const CLIENT_DISCONNECTED = "client_disconnected";

export interface LlmGatewayRuntime {
  config: GatewayConfig;
  registry: RegistryReader;
  resolveCaller: CallerResolver;
  /** CSRF seam (dev-mode §5.4): edge = exact same-origin; dev-gateway = allowlist. */
  checkOrigin: OriginCheck;
  /** Per-IP limiter for the anonymous tier (public apps); null disables it. */
  anonLimiter: IpRateLimiter | null;
  /** Null when no vendor key is configured — the capability 503s. */
  provider: LlmProvider | null;
  usage: UsageStore | null;
  /** Caps metered quota denials per (app, env). null => uncapped (tests). */
  denialThrottle: DenialThrottle | null;
  /** Platform-wide daily LLM ceiling in USD; `0` disables. */
  platformCeilingDollars: number;
  /** Concurrency control; null disables every cap (tests that do not exercise it). */
  concurrency: {
    leases: LeaseStore;
    gate: ReplicaGate | null;
    maxAppInFlight: number;
    maxUserInFlight: number;
  } | null;
  /** Wall-clock deadline for one upstream call, ms. Also bounds the lease TTL. */
  maxCallMs: number;
}

/**
 * Seconds until the next local midnight in the edge process timezone. The
 * database day window uses `date_trunc('day', now())` in the session timezone,
 * so the edge and Postgres must agree (both UTC on Container Apps and the dev
 * container). The value is advisory for `retry-after`.
 */
export function secondsUntilNextLocalMidnight(now = new Date()): number {
  const next = new Date(now);
  next.setHours(24, 0, 0, 0);
  return Math.max(1, Math.ceil((next.getTime() - now.getTime()) / 1000));
}

/**
 * Build the LLM gateway handler for a given wire `codec`. The handler owns all
 * policy + metering and speaks the neutral shape; the codec owns the request/
 * response envelope. `nativeCodec` (default) is `POST /_api/llm/chat`; the OpenAI
 * codec backs `/_api/openai/v1/chat/completions`. Same runtime, same guarantees.
 *
 * `route` is the `http.route` the span records — the codec owns the wire format,
 * not the URL, so the OpenAI surface passes `ROUTE_OPENAI` rather than letting
 * its calls masquerade as `/_api/llm/chat` in traces.
 */
export function makeLlmHandler(
  rt: LlmGatewayRuntime,
  codec: LlmWireCodec = nativeCodec,
  route: string = ROUTE_LLM,
) {
  async function handleLlmChat(
    req: FastifyRequest,
    reply: FastifyReply,
    slug: string,
  ): Promise<void> {
    const entry = resolveServingEntry(rt.registry, slug, reply);
    if (!entry) return;

    // Authn: a fetch with no/expired session gets 401 (the gate handles the
    // navigation-vs-fetch split and refresh-due 401 for /_api/*). On `public`
    // apps the caller is anonymous and the gate is skipped (app-data §6).
    const caller = await rt.resolveCaller(req, reply, entry);
    if (!caller) return;
    const identity = meterIdentity(caller);
    // Kept as its own binding on purpose: `userOid` alone crosses the egress
    // trust boundary below, and the captured labels must not follow it there —
    // AttestedInstructionSchema is deliberately the opaque id and nothing more.
    const { userOid } = identity;

    // Per-IP cap for the anonymous tier (public apps): an anonymous caller has
    // no per-user budget, so cap by IP (app-data design §7). Not metered — a
    // ledger row per throttled call is itself a write-amplification vector.
    if (await anonRateLimited(rt.anonLimiter, req, entry, caller)) {
      codec.error(reply, 429, "rate_limited", "per-IP request budget exhausted");
      return;
    }

    // CSRF: a sibling subdomain must not POST to this app's gateway on the
    // user's session. SameSite doesn't cover cross-subdomain; Origin does.
    if (!rt.checkOrigin(req, entry)) {
      codec.error(reply, 403, "forbidden", "Origin not allowed");
      return;
    }

    // Capability must be configured on this edge (a vendor key is present).
    if (!rt.provider || !rt.usage) {
      codec.error(reply, 503, "capability_unavailable", "LLM capability is not configured");
      return;
    }

    const parsed = codec.parse(req.body);
    if (!parsed.ok) {
      codec.error(reply, parsed.status, parsed.code, parsed.message, parsed.param);
      return;
    }
    const chat = parsed.chat;

    // Authz: the app must hold an LLM grant and the model must be allowlisted
    // (manifest capabilities.llm — §6.3).
    if (!entry.llm) {
      codec.error(reply, 403, "forbidden", "this app has no LLM capability");
      return;
    }
    if (!entry.llm.models.includes(chat.model)) {
      codec.error(reply, 403, "model_not_allowed", `model "${chat.model}" is not allowed`);
      return;
    }
    // Fail-safe: a model with no price can't be cost-gated, so refuse it rather
    // than serve it for free. The curated catalog == the priced catalog
    // (@azx-pbc/shared), so this only bites a model that slipped past curation.
    if (priceForModel(chat.model) === undefined) {
      codec.error(reply, 403, "model_not_allowed", `model "${chat.model}" has no price configured`);
      return;
    }
    // Structured output is a per-model capability, not a per-vendor one (ADR-0034).
    // Refuse here rather than let the upstream reject it, so the app gets a clear
    // 400 naming the field instead of an opaque 502 after a round trip.
    if (chat.responseFormat && !supportsStructuredOutputs(chat.model)) {
      codec.error(
        reply,
        400,
        "validation_failed",
        `model "${chat.model}" does not support structured output`,
        "responseFormat",
      );
      return;
    }
    // The model is priced/allowed, but its upstream family may not be wired on
    // this edge (a routing provider with only one vendor configured). 503 before
    // opening a stream rather than failing mid-flight.
    if (rt.provider.supports && !rt.provider.supports(chat.model)) {
      codec.error(
        reply,
        503,
        "capability_unavailable",
        `model "${chat.model}" has no configured upstream`,
      );
      return;
    }

    // Quota (block-new): if the app is already at/over its daily *or* rolling-
    // hour USD budget, refuse before sending anything upstream. An in-flight
    // request is never cut — including when the client hangs up or a deadline
    // fires; those are not quota cuts. Both windows read the frozen costMicroUsd column.
    const usage = rt.usage;
    const recordDenial = async (reason: AdmissionDenialReason, errorDetail?: string) => {
      meterGatewayCall({ appId: entry.appId, capability: "llm", outcome: "quota_blocked" });
      meterAdmissionDenied({ appId: entry.appId, capability: "llm", reason });
      trace.getActiveSpan()?.setAttribute(ATTR_REASON, reason);
      const decision = rt.denialThrottle
        ? await rt.denialThrottle.admit(entry.appId, caller.env, "llm")
        : { meter: true as const, suppressedAt: undefined };
      if (decision.suppressedAt !== undefined) {
        req.log.warn(
          { appId: entry.appId, env: caller.env, reason, attempts: decision.suppressedAt },
          "quota-denial metering suppressed: this app is over its denial budget for the window",
        );
      }
      if (decision.meter) {
        await usage
          .record({
            appId: entry.appId,
            env: caller.env,
            ...identity,
            capability: "llm",
            model: chat.model,
            inputTokens: 0,
            outputTokens: 0,
            costMicroUsd: 0,
            outcome: "quota_blocked",
            ...(errorDetail ? { errorDetail } : {}),
          })
          .catch(() => {});
      }
    };
    // An unset budget is the install default, never unlimited. 0 is the operator's explicit
    // "no default" (a one-organization install, ADR-0028).
    const cap = entry.llm.dollarsPerDay ?? rt.config.llm.defaultDollarsPerDay;
    if (cap > 0) {
      const capMicro = cap * 1_000_000;
      const { todayMicro, hourMicro } = await usage.llmSpendMicroUsd(entry.appId, caller.env);
      const overDay = todayMicro >= capMicro;
      const overBurst = hourMicro >= capMicro * BURST_BUDGET_FRACTION;
      if (overDay || overBurst) {
        const reason: AdmissionDenialReason = overDay ? "app_budget_day" : "app_budget_burst";
        await recordDenial(reason);
        // Day cap is the harder stop ("done for the day"); prefer its message.
        if (overDay) {
          codec.error(reply, 429, "quota_exceeded", "daily spend budget exhausted");
        } else {
          codec.error(reply, 429, "rate_limited", "burst spend budget exhausted — retry shortly");
        }
        return;
      }
    }

    // Platform ceiling after the per-app gate: overshoot is at most the ceiling plus
    // calls admitted before the per-replica cache (PLATFORM_SPEND_CACHE_MS) catches up.
    if (rt.platformCeilingDollars > 0) {
      let platform: LlmSpend;
      try {
        platform = await usage.platformLlmSpendMicroUsd(caller.env);
      } catch (err) {
        req.log.warn(
          { err, event: "gateway.platform_spend_unavailable" },
          "platform spend read failed",
        );
        reply.header("retry-after", "5");
        codec.error(reply, 503, "capability_unavailable", "platform budget check unavailable");
        return;
      }
      if (platform.todayMicro >= rt.platformCeilingDollars * 1_000_000) {
        await recordDenial("platform_ceiling", "platform_ceiling");
        reply.header("retry-after", String(secondsUntilNextLocalMidnight()));
        codec.error(
          reply,
          503,
          "capability_unavailable",
          "platform LLM budget exhausted for today",
        );
        return;
      }
    }

    const conc = rt.concurrency;
    let release: (() => Promise<void>) | null = null;
    if (conc) {
      const refuse = (reason: AdmissionDenialReason, message: string): void => {
        meterAdmissionDenied({ appId: entry.appId, capability: "llm", reason });
        trace.getActiveSpan()?.setAttribute(ATTR_REASON, reason);
        reply.header("retry-after", "1");
        codec.error(reply, 503, "capability_unavailable", message);
      };
      if (conc.gate && !conc.gate.tryEnter()) {
        refuse("concurrency_replica", "this replica is at its in-flight LLM limit");
        return;
      }
      const requests: LeaseRequest[] = [
        { scope: `llm:app:${entry.appId}`, cap: conc.maxAppInFlight },
        // An anonymous caller shares one identity; the per-IP limiter covers them.
        ...(caller.authenticated
          ? [{ scope: `llm:user:${entry.appId}:${userOid}`, cap: conc.maxUserInFlight }]
          : []),
      ];
      let acquired: AcquireResult;
      try {
        acquired = await conc.leases.acquire(requests, rt.maxCallMs + LEASE_GRACE_MS);
      } catch (err) {
        conc.gate?.leave();
        req.log.warn({ err, event: "gateway.lease_unavailable" }, "lease acquire failed");
        reply.header("retry-after", "5");
        codec.error(reply, 503, "capability_unavailable", "concurrency check unavailable");
        return;
      }
      if (!acquired.ok) {
        conc.gate?.leave();
        const app = acquired.scope.startsWith("llm:app:");
        refuse(
          app ? "concurrency_app" : "concurrency_user",
          app
            ? "too many concurrent LLM calls for this app"
            : "too many concurrent LLM calls for this user",
        );
        return;
      }
      release = async () => {
        conc.gate?.leave();
        await conc.leases
          .release(acquired.leaseId)
          .catch((err: unknown) =>
            req.log.warn({ err, event: "gateway.lease_release_failed" }, "lease release failed"),
          );
      };
    }

    try {
      // Admitted. Abort the upstream if the client goes away.
      //
      // Watch the *response*, not the request. `req.raw` emits 'close' when the
      // request body finishes arriving, which on this route has already happened
      // before the handler runs (Fastify's JSON parser drained it), so a listener
      // here was attached after the event and never fired at all — the disconnect
      // abort below has never actually run. The ServerResponse's 'close' fires when
      // the connection goes away, and `writableEnded` separates "we finished
      // answering" from "they hung up". Fastify's own `request.signal` is wired to
      // the same unguarded `req.on('close')` — do not substitute it.
      //
      // `writableEnded`, not `writableFinished`: the two agree on a real socket,
      // but light-my-request's null socket never settles `writableFinished`, so
      // under `app.inject()` every ordinary response would look like a hang-up.
      const abort = new AbortController();
      let clientGone = false;
      reply.raw.on("close", () => {
        if (reply.raw.writableEnded) return;
        clientGone = true;
        abort.abort();
        // Mark the span so an abandoned stream is filterable. Read off the active
        // context rather than threaded in: the span is opened by the wrapper at
        // the bottom of this factory, and this listener already closes over
        // enough.
        trace.getActiveSpan()?.setAttribute(ATTR_CLIENT_DISCONNECTED, true);
      });

      const startedAt = performance.now();
      let recorded = false;
      let finalStopReason = "end_turn";
      const finalUsage: LlmUsage = {
        inputTokens: 0,
        outputTokens: 0,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
      };
      // What a cut call is charged from, when the vendor never sent `done`.
      const requestBytes =
        Buffer.byteLength(chat.system ?? "", "utf8") +
        chat.messages.reduce((n, m) => n + Buffer.byteLength(m.content, "utf8"), 0);
      let relayedBytes = 0;
      let measured: LlmUsage | undefined;
      let eventsSeen = 0;
      const recordOnce = async (
        outcome: GatewayOutcome,
        extra: { errorDetail?: string; cut?: boolean } = {},
      ): Promise<void> => {
        if (recorded) return;
        recorded = true;
        const durationMs = Math.round(performance.now() - startedAt);
        // `recordOnce` runs after the stream has drained (the handler drives the
        // `for await` itself), so this duration is the real end-to-end time, not
        // time-to-first-header.
        meterGatewayCall({ appId: entry.appId, capability: "llm", outcome, durationMs });
        let stopReason: string | null = finalStopReason;
        let errorDetail = extra.errorDetail ?? null;
        if (extra.cut) {
          const estimate = estimateCutUsage({
            measured,
            requestBytes,
            relayedBytes,
            model: chat.model,
            maxTokens: chat.maxTokens,
          });
          Object.assign(finalUsage, estimate.usage);
          // The default "end_turn" is false for a call that never finished.
          stopReason = null;
          // The marker goes LAST and the text before it is cut to fit: clampRecord truncates
          // errorDetail at ERROR_DETAIL_MAX and would otherwise drop the marker.
          const marker = `;usage=${estimate.basis}`;
          errorDetail =
            truncate(extra.errorDetail ?? "", ERROR_DETAIL_MAX - marker.length - 1) + marker;
          meterCutCharge({ appId: entry.appId, basis: estimate.basis });
          trace.getActiveSpan()?.setAttribute(ATTR_USAGE_BASIS, estimate.basis);
        }
        // Freeze the as-charged cost at write time (micro-USD) from the final
        // token counts + the requested model's current rate. This is what both
        // the spend gate and the portal dollar figures read back.
        const costMicroUsd = Math.round(costUsd({ model: chat.model, ...finalUsage }) * 1_000_000);
        await usage
          .record({
            appId: entry.appId,
            env: caller.env,
            ...identity,
            capability: "llm",
            model: chat.model,
            inputTokens: finalUsage.inputTokens,
            outputTokens: finalUsage.outputTokens,
            cacheReadInputTokens: finalUsage.cacheReadInputTokens,
            cacheCreationInputTokens: finalUsage.cacheCreationInputTokens,
            costMicroUsd,
            outcome,
            durationMs,
            // LLM streams over a 200; the stop reason is the useful signal here.
            stopReason,
            errorDetail,
          })
          .catch((err: unknown) =>
            req.log.warn(
              {
                err,
                event: "gateway.usage_record_failed",
                appId: entry.appId,
                capability: "llm",
                outcome,
              },
              "gateway usage record failed",
            ),
          );
      };

      // Two distinct ids: `requestId` is internal — it correlates the egress call
      // and becomes the attested instruction's `jti` (burned for replay
      // protection), so it must never reach app code. `completionId` is the
      // app-visible `chatcmpl-<id>`. `created` is stamped once so all chunks agree.
      const requestId = randomUUID();
      const ctx: LlmWireContext = {
        completionId: randomUUID(),
        model: chat.model,
        created: Math.floor(Date.now() / 1000),
        corsOrigin: req.devCorsOrigin,
        includeUsage: parsed.includeUsage,
      };
      const deadline = AbortSignal.timeout(rt.maxCallMs);
      const callSignal = AbortSignal.any([abort.signal, deadline, processShutdownSignal()]);
      const events = rt.provider.stream(chat, {
        signal: callSignal,
        appId: entry.appId,
        // The opaque id ONLY — this reaches egress via the attested instruction.
        userOid,
        requestId,
        // The log correlation id, NOT the jti above — see `LlmStreamOpts`.
        correlationId: String(req.id),
        env: caller.env,
      });

      // Whether a schema was requested, so an upstream 400 can name the likely cause
      // (ADR-0034) without blaming a schema the app never sent.
      const structured = chat.responseFormat !== undefined;

      if (chat.stream) {
        let started = false;
        const start = (): void => {
          if (!started) {
            codec.startStream(reply, ctx);
            started = true;
          }
        };
        try {
          for await (const ev of events) {
            if (ev.type === "delta") {
              eventsSeen += 1;
              relayedBytes += Buffer.byteLength(ev.text, "utf8");
              start();
              codec.writeDelta(reply, ctx, ev.text);
            } else if (ev.type === "usage") {
              eventsSeen += 1;
              measured = ev.usage;
            } else {
              measured = ev.usage; // the final counts are measured too
              Object.assign(finalUsage, ev.usage);
              finalStopReason = ev.stopReason;
            }
          }
          start();
          codec.writeDone(reply, ctx, { stopReason: finalStopReason, usage: finalUsage });
          codec.endStream(reply);
          await recordOnce(outcomeFor(finalStopReason));
        } catch (err) {
          // The app hung up: the abort above is what ended this stream, so there is
          // no upstream failure to describe and no socket left to describe it on.
          // Meter it as an `error` carrying a distinct detail — `GatewayOutcome` has
          // no `cancelled` member, and adding one would mean migrating a shared enum
          // for something the detail already distinguishes.
          if (clientGone) {
            await recordOnce("error", { errorDetail: CLIENT_DISCONNECTED, cut: true });
            return;
          }
          const shutdownHit = processShutdownSignal().aborted;
          const deadlineHit = deadline.aborted;
          await recordOnce("error", {
            errorDetail: shutdownHit
              ? "process_shutdown"
              : deadlineHit
                ? "deadline_exceeded"
                : errorDetailOf(err),
            cut: shutdownHit || deadlineHit || eventsSeen > 0,
          });
          const { status, code, message, param, retryAfter } =
            shutdownHit || deadlineHit
              ? {
                  status: 502,
                  code: "internal" as const,
                  message: shutdownHit
                    ? "LLM call ended during platform shutdown"
                    : "LLM call exceeded its time limit",
                  param: undefined,
                  retryAfter: undefined,
                }
              : describeError(err, { structured });
          if (!started) {
            // `start()` is lazy, so a failure before the first delta has written
            // nothing — a real status is still possible, and matches how every other
            // pre-stream refusal on this route (authz, quota, validation) answers.
            if (retryAfter !== undefined) reply.header("retry-after", String(retryAfter));
            codec.error(reply, status, code, message, param);
            return;
          }
          // The head is already out; an in-band error frame is the only channel left.
          codec.writeStreamError(reply, ctx, { code, message });
          codec.endStream(reply);
        }
        return;
      }

      // Non-streaming: accumulate into a single JSON body.
      let content = "";
      try {
        for await (const ev of events) {
          if (ev.type === "delta") {
            eventsSeen += 1;
            relayedBytes += Buffer.byteLength(ev.text, "utf8");
            content += ev.text;
          } else if (ev.type === "usage") {
            eventsSeen += 1;
            measured = ev.usage;
          } else {
            measured = ev.usage; // the final counts are measured too
            Object.assign(finalUsage, ev.usage);
            finalStopReason = ev.stopReason;
          }
        }
        await recordOnce(outcomeFor(finalStopReason));
        codec.sendResponse(reply, ctx, {
          content,
          stopReason: finalStopReason,
          usage: finalUsage,
        });
      } catch (err) {
        // As above: our own abort ended this, not the vendor.
        if (clientGone) {
          await recordOnce("error", { errorDetail: CLIENT_DISCONNECTED, cut: true });
          return;
        }
        const shutdownHit = processShutdownSignal().aborted;
        const deadlineHit = deadline.aborted;
        await recordOnce("error", {
          errorDetail: shutdownHit
            ? "process_shutdown"
            : deadlineHit
              ? "deadline_exceeded"
              : errorDetailOf(err),
          cut: shutdownHit || deadlineHit || eventsSeen > 0,
        });
        const { status, code, message, param, retryAfter } =
          shutdownHit || deadlineHit
            ? {
                status: 502,
                code: "internal" as const,
                message: shutdownHit
                  ? "LLM call ended during platform shutdown"
                  : "LLM call exceeded its time limit",
                param: undefined,
                retryAfter: undefined,
              }
            : describeError(err, { structured });
        // 502 for upstream failures, 400 when the vendor rejected the app's request,
        // 429 (with retry-after) when it throttled one; the code stays within the
        // shared set.
        if (retryAfter !== undefined) reply.header("retry-after", String(retryAfter));
        codec.error(reply, status, code, message, param);
      }
    } finally {
      // `recordOnce` runs on every exit path before this; releasing the lease after
      // the ledger row is what keeps spend visible to the next admission check.
      await release?.();
    }
  }

  /**
   * The span wraps the whole handler, including the pre-admission refusals, so
   * a 401/403/429 is visible as a short span rather than as nothing at all.
   *
   * {@link withRootSpan} ends the span when the handler settles, which for
   * both streaming shapes in this codebase is after the last byte: this one
   * drives its own `for await` over the upstream events, and the fetch-proxy's
   * `return reply.send(stream)` resolves through Fastify's thenable `Reply`
   * only once the response finishes. One helper covers both — see the note on
   * `withRootSpan` for the measurement, and `spans.test.ts` for the guard.
   */
  return (req: FastifyRequest, reply: FastifyReply, slug: string): Promise<void> =>
    withRootSpan(
      SPAN_LLM,
      { [ATTR_CAPABILITY]: "llm", [ATTR_APP_SLUG]: slug, "http.route": route },
      () => handleLlmChat(req, reply, slug),
      { reply },
    );
}

/** A clean completion whose stop reason is a refusal meters as `refusal`, not `ok`. */
function outcomeFor(stopReason: string): GatewayOutcome {
  return stopReason === "refusal" ? "refusal" : "ok";
}

/**
 * Map a provider/abort failure to a stable status + code + safe message.
 *
 * A **400 from the vendor means the app's request was invalid**, not that the
 * upstream flaked — under a schema, almost always one outside the strict JSON
 * Schema subset (ADR-0034). Reporting that as `502 internal` told the app to retry
 * something that can never succeed, and attributed an app bug to the platform.
 * `LlmProviderError` already carries the status, so this needs no new plumbing.
 *
 * An **upstream 429 is a throttle, not an outage** — it passes through as
 * `429 rate_limited` so the app's SDK retry/backoff engages instead of reading
 * a platform failure, with the vendor's `retry-after` when we have one (a
 * fixed 5s otherwise, the same nudge `sendUnavailable` gives). `rate_limited`
 * is already in the shared code set, and the OpenAI codec maps it to
 * `rate_limit_exceeded`. Deliberately no 5xx passthrough: a vendor 5xx *is* an
 * upstream failure, and 502 says so; a 503 here would also collide with the
 * platform's own `capability_unavailable` meaning.
 *
 * The vendor's own message is **never echoed** — it can quote request content, and
 * on an auth failure it can quote the key. `errorDetailOf` keeps the full text in
 * the ledger (internal-only) for the owner instead.
 */
function describeError(
  err: unknown,
  opts: { structured: boolean },
): { status: number; code: ApiErrorCode; message: string; param?: string; retryAfter?: number } {
  if (err instanceof LlmProviderError) {
    if (err.upstreamStatus === 400) {
      // Only blame the schema when one was actually sent; a 400 can also be a bad
      // sampling param or an over-long prompt.
      return opts.structured
        ? {
            status: 400,
            code: "validation_failed",
            message:
              "the upstream rejected this request — check `responseFormat.schema` against the strict JSON Schema subset (every property in `required`, `additionalProperties: false`, no recursion)",
            param: "responseFormat",
          }
        : {
            status: 400,
            code: "validation_failed",
            message: "the upstream rejected this request as invalid",
          };
    }
    if (err.upstreamStatus === 429) {
      return {
        status: 429,
        code: "rate_limited",
        message: "upstream model is rate limited — retry shortly",
        retryAfter: err.retryAfter ?? 5,
      };
    }
    return { status: 502, code: "internal", message: "upstream LLM request failed" };
  }
  return { status: 502, code: "internal", message: "LLM request failed" };
}
