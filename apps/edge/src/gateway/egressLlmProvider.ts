import { Readable } from "node:stream";
import type { LlmChatRequest } from "@azx-pbc/shared";
import {
  type EgressLlmVendor,
  type LlmProvider,
  type LlmStreamEvent,
  type LlmStreamOpts,
  LlmProviderError,
} from "./provider.js";
import type { EgressProvider } from "./egressProvider.js";
import { mintInstruction } from "./instruction.js";

/**
 * The LLM provider that routes through `helix-egress` (secrets design §1, §4). It
 * keeps the edge out of the credential path entirely: the vendor key is a
 * `platform`-scoped secret egress resolves and injects, so the edge never holds
 * it and rotation in the portal needs no edge restart.
 *
 * The division of labour mirrors the fetch-proxy. All LLM *policy* — session
 * gate, model allowlist, USD budget, metering — stays in the handler
 * (`llm.ts`); this provider only builds the upstream request, mints an attested
 * `llm` instruction, and hands the call to egress, then parses the SSE that
 * streams back. It is vendor-agnostic: an {@link EgressLlmVendor} descriptor
 * supplies the path, headers, body builder, and stream mapper, so the same class
 * serves Anthropic and any OpenAI-compatible upstream.
 */
export class EgressLlmProvider implements LlmProvider {
  readonly #vendor: EgressLlmVendor;
  readonly #egress: EgressProvider;
  readonly #instructionKey: Buffer;
  readonly #hopTimeoutMs: number;

  constructor(
    vendor: EgressLlmVendor,
    egress: EgressProvider,
    instructionKey: Buffer,
    hopTimeoutMs: number,
  ) {
    this.#vendor = vendor;
    this.#egress = egress;
    this.#instructionKey = instructionKey;
    this.#hopTimeoutMs = hopTimeoutMs;
  }

  async *stream(req: LlmChatRequest, opts: LlmStreamOpts): AsyncIterable<LlmStreamEvent> {
    const origin = new URL(this.#vendor.endpoint).origin;
    const instruction = await mintInstruction(
      {
        appId: opts.appId,
        userOid: opts.userOid,
        capability: "llm",
        origin,
        connection: this.#vendor.connection,
        requestId: opts.requestId,
        env: opts.env,
        method: "POST",
        path: this.#vendor.path,
      },
      this.#instructionKey,
    );

    const res = await this.#egress.proxy({
      instruction,
      target: `${origin}${this.#vendor.path}`,
      method: "POST",
      headers: {
        ...this.#vendor.headers,
        "content-type": "application/json",
        accept: "text/event-stream",
      },
      // Send the JSON body whole (string → undici sets content-length). NOT
      // Readable.from(string): that is an object-mode char stream → empty body.
      body: this.#vendor.buildBody(req),
      signal: opts.signal,
      correlationId: opts.correlationId,
      hopTimeoutMs: this.#hopTimeoutMs,
    });

    if (res.status !== 200) {
      // A 403 here is egress refusing the connection — typically the platform
      // secret is unset/misnamed. Surface the upstream status to the handler.
      const text = await readText(res.body);
      let egressCode: string | undefined;
      try {
        const parsed = JSON.parse(text) as { code?: string };
        if (typeof parsed.code === "string") egressCode = parsed.code;
      } catch {
        // Opaque body — the handler falls back to status-based mapping.
      }
      throw new LlmProviderError(
        `egress llm call failed (${res.status}): ${text}`,
        res.status,
        // Egress forwards the upstream's `retry-after` (it is not on the
        // response blocklist, and a non-200 streams back through the same
        // header loop as a 200). Coerce-or-drop like `wireCount`: an integer
        // delay-seconds value travels, an HTTP-date or junk does not.
        retryAfterSeconds(res.headers["retry-after"]),
        egressCode,
      );
    }

    yield* this.#vendor.mapStream(res.body);
  }

  // The egress provider is shared with the fetch path and owned by the server
  // (closed via `egress.close()` on shutdown) — nothing for this provider to own.
  async close(): Promise<void> {}
}

async function readText(body: Readable, max = 200): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of body) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    chunks.push(buf);
    total += buf.length;
    if (total >= max) break;
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/** Coerce an upstream `retry-after` header to integer delay-seconds, or undefined. */
function retryAfterSeconds(raw: string | string[] | undefined): number | undefined {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (value === undefined) return undefined;
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 ? n : undefined;
}
