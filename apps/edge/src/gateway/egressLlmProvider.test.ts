import { randomBytes } from "node:crypto";
import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import { jwtVerify } from "jose";
import type { LlmChatRequest } from "@azx-pbc/shared";
import { EgressLlmProvider } from "./egressLlmProvider.js";
import { LlmProviderError, anthropicVendor, type LlmStreamEvent } from "./provider.js";
import type { EgressProvider, EgressRequest, EgressResponse } from "./egressProvider.js";
import { deriveInstructionKey } from "./instruction.js";

/**
 * The egress-routed LLM provider keeps the edge out of the credential path: it
 * mints an `llm` instruction naming the platform connection and lets egress hold
 * the key. These assert the instruction it mints, that it parses the relayed SSE
 * identically to the direct provider, and that an egress refusal surfaces.
 */

const SECRET = randomBytes(32);
const KEY = deriveInstructionKey(SECRET);

const CHAT: LlmChatRequest = {
  model: "claude-opus-4-8",
  messages: [{ role: "user", content: "hi" }],
  maxTokens: 256,
  stream: true,
};

const SSE = [
  `event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":10,"output_tokens":0}}}`,
  `event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}`,
  `event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}`,
  `event: message_stop\ndata: {"type":"message_stop"}`,
  "",
].join("\n\n");

function stubEgress(
  response: Partial<EgressResponse>,
  onProxy?: (req: EgressRequest) => void,
): EgressProvider {
  return {
    proxy: async (req: EgressRequest): Promise<EgressResponse> => {
      onProxy?.(req);
      return {
        status: 200,
        headers: { "content-type": "text/event-stream" },
        body: Readable.from(SSE),
        outcome: "ok",
        ...response,
      };
    },
    close: async () => {},
  };
}

const TEST_LLM_HOP_TIMEOUT_MS = 660_000;

function provider(egress: EgressProvider): EgressLlmProvider {
  return new EgressLlmProvider(
    anthropicVendor({
      endpoint: "https://api.anthropic.com",
      anthropicVersion: "2023-06-01",
      connection: "anthropic",
    }),
    egress,
    KEY,
    TEST_LLM_HOP_TIMEOUT_MS,
  );
}

const opts = {
  signal: new AbortController().signal,
  appId: "app-1",
  userOid: "user-1",
  userName: null,
  userEmail: null,
  userKind: "user" as const,
  requestId: "req-1",
  correlationId: "req-corr-test",
  env: "prod" as const,
};

async function collect(events: AsyncIterable<LlmStreamEvent>): Promise<LlmStreamEvent[]> {
  const out: LlmStreamEvent[] = [];
  for await (const ev of events) out.push(ev);
  return out;
}

describe("EgressLlmProvider", () => {
  it("mints an llm instruction naming the platform connection and the messages target", async () => {
    let captured: EgressRequest | undefined;
    const p = provider(stubEgress({}, (req) => (captured = req)));
    await collect(p.stream(CHAT, opts));

    expect(captured?.target).toBe("https://api.anthropic.com/v1/messages");
    expect(captured?.method).toBe("POST");
    expect(captured?.headers["anthropic-version"]).toBe("2023-06-01");

    // Body is sent whole as parseable JSON (not an object-mode char stream that
    // serializes empty — regression guard for the "zero-length document" bug).
    expect(typeof captured?.body).toBe("string");
    const sent = JSON.parse(captured!.body as string);
    expect(sent.model).toBe("claude-opus-4-8");
    expect(sent.stream).toBe(true);
    expect(sent.messages).toEqual([{ role: "user", content: "hi" }]);

    const { payload } = await jwtVerify(captured!.instruction, KEY);
    expect(payload.capability).toBe("llm");
    expect(payload.connection).toBe("anthropic");
    expect(payload.origin).toBe("https://api.anthropic.com");
    expect(payload.appId).toBe("app-1");
    expect(payload.userOid).toBe("user-1");
  });

  // ADR-0046 — the Foundry shape: origin-only endpoint + path override. The
  // instruction binds the origin (not the prefix), and the target egress dials
  // is the two composed — the pairing the egress path re-check then enforces.
  it("composes the Foundry target from an origin-only endpoint and a path override", async () => {
    let captured: EgressRequest | undefined;
    const p = new EgressLlmProvider(
      anthropicVendor({
        endpoint: "https://contoso.services.ai.azure.com",
        anthropicVersion: "2023-06-01",
        connection: "foundry",
        path: "/anthropic/v1/messages",
      }),
      stubEgress({}, (req) => (captured = req)),
      KEY,
      TEST_LLM_HOP_TIMEOUT_MS,
    );
    await collect(p.stream(CHAT, opts));

    expect(captured?.target).toBe("https://contoso.services.ai.azure.com/anthropic/v1/messages");
    const { payload } = await jwtVerify(captured!.instruction, KEY);
    expect(payload.origin).toBe("https://contoso.services.ai.azure.com");
    expect(payload.path).toBe("/anthropic/v1/messages");
    expect(payload.connection).toBe("foundry");
  });

  it("parses the relayed SSE into delta + done events", async () => {
    const p = provider(stubEgress({}));
    const events = await collect(p.stream(CHAT, opts));
    expect(events).toEqual([
      {
        type: "usage",
        usage: {
          inputTokens: 10,
          outputTokens: 0,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
      },
      { type: "delta", text: "Hello" },
      {
        type: "usage",
        usage: {
          inputTokens: 10,
          outputTokens: 5,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
      },
      {
        type: "done",
        stopReason: "end_turn",
        usage: {
          inputTokens: 10,
          outputTokens: 5,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
      },
    ]);
  });

  it("surfaces an egress refusal (e.g. platform secret unset) as LlmProviderError", async () => {
    const p = provider(
      stubEgress({
        status: 403,
        outcome: "refusal",
        body: Readable.from(JSON.stringify({ code: "forbidden", message: "connection not found" })),
      }),
    );
    await expect(collect(p.stream(CHAT, opts))).rejects.toMatchObject({
      name: "LlmProviderError",
      upstreamStatus: 403,
    });
    expect(LlmProviderError).toBeDefined();
  });

  it("carries the upstream retry-after (integer delay-seconds) on the error", async () => {
    const p = provider(
      stubEgress({
        status: 429,
        outcome: "upstream_throttled",
        headers: { "content-type": "application/json", "retry-after": "30" },
        body: Readable.from(JSON.stringify({ error: { code: "429", message: "Rate limit" } })),
      }),
    );
    await expect(collect(p.stream(CHAT, opts))).rejects.toMatchObject({
      name: "LlmProviderError",
      upstreamStatus: 429,
      retryAfter: 30,
    });
  });

  it("drops a retry-after that isn't integer delay-seconds (HTTP-date, junk, absent)", async () => {
    for (const retryAfter of ["Wed, 23 Sep 2026 12:00:00 GMT", "soon", undefined]) {
      const p = provider(
        stubEgress({
          status: 429,
          outcome: "upstream_throttled",
          ...(retryAfter === undefined
            ? {}
            : { headers: { "content-type": "application/json", "retry-after": retryAfter } }),
          body: Readable.from(JSON.stringify({ error: { code: "429" } })),
        }),
      );
      await expect(collect(p.stream(CHAT, opts))).rejects.toMatchObject({
        name: "LlmProviderError",
        upstreamStatus: 429,
        retryAfter: undefined,
      });
    }
  });
});
