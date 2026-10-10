import type { Readable } from "node:stream";
import { Agent, request } from "undici";
import { INSTRUCTION_HEADER, METHOD_HEADER, OUTCOME_HEADER, TARGET_HEADER } from "@azx-pbc/shared";
import { context, propagation } from "@opentelemetry/api";
import { REQUEST_ID_HEADER } from "@azx-pbc/shared/logging";

/**
 * The edge → egress seam (fetch-proxy design §7), shaped like the `LlmProvider`:
 * the edge has authorized a `/_api/fetch` call and forwards it, with the signed
 * attested instruction, to the mechanism-plane service. The edge holds no secret
 * and has no internet route — it can only ask egress to make a call it already
 * authorized. The upstream body streams back through here untouched.
 */
export interface EgressRequest {
  /** The signed attested instruction JWT. */
  instruction: string;
  /** Full target URL (origin already matched the instruction at the edge). */
  target: string;
  method: string;
  /** Safelisted request headers to forward upstream. */
  headers: Record<string, string>;
  /**
   * Request body for non-GET/HEAD methods; null otherwise. A `Readable` streams
   * (the fetch-proxy forwards the app's `req.raw`); a `string`/`Buffer` is sent
   * whole with a content-length (the LLM path sends a built JSON body — do NOT
   * wrap it in `Readable.from(string)`, which yields chars in object mode and
   * undici serializes as an empty body).
   */
  body: Readable | Buffer | string | null;
  signal: AbortSignal;
  /**
   * The edge's own request id, so both halves of this call land on one value in
   * two different Log Analytics workspaces.
   *
   * **Not** the instruction's `jti`/`requestId`, which is a single-use replay
   * nonce and must stay one (ADR-0037 decision 7 says so in as many words).
   * Two ids, two jobs; keeping them visibly separate — including in the field
   * name — is what stops a future "make the id survive a retry" from becoming a
   * replay bug.
   */
  correlationId: string;
  /**
   * Per-hop idle timeout (undici `headersTimeout` / `bodyTimeout`). LLM calls
   * set this above the edge deadline so the deadline abort wins first.
   */
  hopTimeoutMs?: number;
}

export interface EgressResponse {
  status: number;
  headers: Record<string, string | string[]>;
  body: Readable;
  /** The egress outcome label (OUTCOME_HEADER), for the edge to meter. */
  outcome: string;
}

export interface EgressProvider {
  proxy(req: EgressRequest): Promise<EgressResponse>;
  close(): Promise<void>;
}

export class EgressProviderError extends Error {}

/** undici-backed client to the egress service's internal `/proxy` endpoint. */
export class HttpEgressProvider implements EgressProvider {
  readonly #base: string;
  readonly #dispatcher: Agent;
  readonly #timeoutMs: number;

  constructor(egressUrl: string, opts: { timeoutMs?: number } = {}) {
    this.#base = egressUrl.replace(/\/+$/, "");
    this.#timeoutMs = opts.timeoutMs ?? 30_000;
    // Per-request `headersTimeout` / `bodyTimeout` override these defaults on each hop.
    this.#dispatcher = new Agent({
      headersTimeout: this.#timeoutMs,
      bodyTimeout: this.#timeoutMs,
    });
  }

  async proxy(req: EgressRequest): Promise<EgressResponse> {
    // Trace context, inward only (ADR-0037 decision 7). `propagation.inject`
    // writes nothing when no SDK is registered — the platform's default state —
    // so this is a no-op delta until a collector is configured.
    //
    // Built as its own object rather than written straight into the header
    // literal so it can be spread AFTER `req.headers`: those are the safelisted
    // headers forwarded from the app's own request, and an app that sends
    // `traceparent` must not be able to shadow ours. (It also never reaches
    // here — `traceparent` is not on `REQUEST_HEADER_SAFELIST` — but the
    // ordering is the guarantee that does not depend on that list.)
    const traceContext: Record<string, string> = {};
    propagation.inject(context.active(), traceContext);

    try {
      const hopTimeoutMs = req.hopTimeoutMs ?? this.#timeoutMs;
      const res = await request(`${this.#base}/proxy`, {
        method: "POST",
        // Platform headers go AFTER the spread: `req.headers` is the
        // safelisted set forwarded from the app's own request, and an app that
        // sends `x-helix-request-id` must not be able to shadow ours.
        headers: {
          ...req.headers,
          [INSTRUCTION_HEADER]: req.instruction,
          [TARGET_HEADER]: req.target,
          [METHOD_HEADER]: req.method,
          [REQUEST_ID_HEADER]: req.correlationId,
          ...traceContext,
        },
        body: req.body ?? undefined,
        signal: req.signal,
        dispatcher: this.#dispatcher,
        headersTimeout: hopTimeoutMs,
        bodyTimeout: hopTimeoutMs,
      });
      const outcome = res.headers[OUTCOME_HEADER];
      return {
        status: res.statusCode,
        headers: res.headers as Record<string, string | string[]>,
        body: res.body,
        outcome: typeof outcome === "string" ? outcome : "error",
      };
    } catch (err) {
      throw new EgressProviderError("egress request failed", { cause: err });
    }
  }

  async close(): Promise<void> {
    await this.#dispatcher.close();
  }
}
