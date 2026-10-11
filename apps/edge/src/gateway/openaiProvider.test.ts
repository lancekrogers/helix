import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import type { LlmChatRequest } from "@azx-pbc/shared";
import {
  LlmProviderError,
  mapOpenAiStream,
  openAiRequestBody,
  type LlmProvider,
  type LlmStreamEvent,
  type LlmStreamOpts,
} from "./provider.js";
import { RoutingLlmProvider } from "./routingLlmProvider.js";

const OPTS: LlmStreamOpts = {
  signal: new AbortController().signal,
  appId: "app-1",
  userOid: "user-1",
  requestId: "req-1",
  correlationId: "req-corr-test",
  env: "prod",
};

function req(over: Partial<LlmChatRequest> = {}): LlmChatRequest {
  return {
    model: "gpt-4o",
    messages: [{ role: "user", content: "hi" }],
    maxTokens: 256,
    stream: true,
    ...over,
  };
}

async function collect(events: AsyncIterable<LlmStreamEvent>): Promise<LlmStreamEvent[]> {
  const out: LlmStreamEvent[] = [];
  for await (const ev of events) out.push(ev);
  return out;
}

describe("openAiRequestBody — structured output (ADR-0034)", () => {
  const SCHEMA = { type: "object", properties: { a: { type: "string" } } };

  it("emits response_format.json_schema, defaulting the name OpenAI requires", () => {
    const body = JSON.parse(
      openAiRequestBody(req({ responseFormat: { type: "json_schema", schema: SCHEMA } })),
    );
    expect(body.response_format).toEqual({
      type: "json_schema",
      json_schema: { name: "response", schema: SCHEMA, strict: true },
    });
  });

  it("forwards an explicit name and always requests strict enforcement", () => {
    const body = JSON.parse(
      openAiRequestBody(
        req({ responseFormat: { type: "json_schema", name: "place", schema: SCHEMA } }),
      ),
    );
    // strict is unconditionally true: Anthropic can only enforce, so best-effort
    // here would make the same request behave differently per vendor (ADR-0034).
    expect(body.response_format.json_schema).toEqual({
      name: "place",
      schema: SCHEMA,
      strict: true,
    });
  });

  it("omits response_format entirely when the app didn't ask for one", () => {
    expect(JSON.parse(openAiRequestBody(req()))).not.toHaveProperty("response_format");
  });
});

describe("openAiRequestBody", () => {
  it("hoists system into a leading system message and uses max_tokens for chat models", () => {
    const body = JSON.parse(openAiRequestBody(req({ system: "be terse" })));
    expect(body.messages[0]).toEqual({ role: "system", content: "be terse" });
    expect(body.messages[1]).toEqual({ role: "user", content: "hi" });
    expect(body.max_tokens).toBe(256);
    expect(body.max_completion_tokens).toBeUndefined();
    expect(body.stream).toBe(true);
    expect(body.stream_options).toEqual({ include_usage: true });
  });

  it("omits the upstream cap when maxTokens is unset (→ model max)", () => {
    const body = JSON.parse(openAiRequestBody(req({ maxTokens: undefined })));
    expect(body.max_tokens).toBeUndefined();
    expect(body.max_completion_tokens).toBeUndefined();
  });

  it("floors max_completion_tokens for reasoning models", () => {
    // requested 256 is below the gpt-5-mini floor (25k) → floored so reasoning has room.
    const floored = JSON.parse(openAiRequestBody(req({ model: "gpt-5-mini", maxTokens: 256 })));
    expect(floored.max_completion_tokens).toBe(25_000);
    expect(floored.max_tokens).toBeUndefined();
    // unset also gets the floor, never an unbounded/omitted budget.
    const unset = JSON.parse(openAiRequestBody(req({ model: "gpt-5-mini", maxTokens: undefined })));
    expect(unset.max_completion_tokens).toBe(25_000);
  });

  it("forwards temperature, top_p and stop when present", () => {
    const body = JSON.parse(
      openAiRequestBody(req({ temperature: 0.2, topP: 0.5, stop: ["\n\n"] })),
    );
    expect(body.temperature).toBe(0.2);
    expect(body.top_p).toBe(0.5);
    expect(body.stop).toEqual(["\n\n"]);
  });
});

describe("mapOpenAiStream", () => {
  const chunk = (o: unknown): string => `data: ${JSON.stringify(o)}\n\n`;

  it("maps content deltas + usage to neutral events, ignoring [DONE]", async () => {
    const sse =
      chunk({ choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] }) +
      chunk({ choices: [{ index: 0, delta: { content: "Hello" }, finish_reason: null }] }) +
      chunk({ choices: [{ index: 0, delta: { content: " world" }, finish_reason: null }] }) +
      chunk({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }) +
      // completion_tokens already folds in reasoning tokens — used verbatim.
      chunk({
        choices: [],
        usage: {
          prompt_tokens: 10,
          completion_tokens: 7,
          completion_tokens_details: { reasoning_tokens: 3 },
        },
      }) +
      "data: [DONE]\n\n";

    const events = await collect(mapOpenAiStream(Readable.from([Buffer.from(sse)])));
    expect(events).toEqual([
      { type: "delta", text: "Hello" },
      { type: "delta", text: " world" },
      {
        type: "usage",
        usage: {
          inputTokens: 10,
          outputTokens: 7,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
      },
      {
        type: "done",
        stopReason: "end_turn",
        usage: {
          inputTokens: 10,
          outputTokens: 7,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
      },
    ]);
  });

  const usageChunk = chunk({
    choices: [],
    usage: { prompt_tokens: 1, completion_tokens: 1 },
  });

  it("maps finish_reason length -> max_tokens and content_filter -> refusal", async () => {
    for (const [finish, stopReason] of [
      ["length", "max_tokens"],
      ["content_filter", "refusal"],
    ] as const) {
      const sse =
        chunk({ choices: [{ index: 0, delta: { content: "x" }, finish_reason: null }] }) +
        chunk({ choices: [{ index: 0, delta: {}, finish_reason: finish }] }) +
        usageChunk +
        "data: [DONE]\n\n";
      const events = await collect(mapOpenAiStream(Readable.from([Buffer.from(sse)])));
      const done = events.at(-1);
      expect(done?.type === "done" && done.stopReason).toBe(stopReason);
    }
  });

  it("maps a structured-output refusal (delta.refusal) to a refusal stop reason", async () => {
    const sse =
      chunk({
        choices: [
          { index: 0, delta: { refusal: "I can't help with that" }, finish_reason: "stop" },
        ],
      }) +
      usageChunk +
      "data: [DONE]\n\n";
    const events = await collect(mapOpenAiStream(Readable.from([Buffer.from(sse)])));
    const done = events.at(-1);
    expect(done?.type === "done" && done.stopReason).toBe("refusal");
  });

  it("throws (records as error) when the stream ends without a usage block", async () => {
    // Content deltas but the trailing usage chunk never arrives (truncated). An
    // all-zero $0 `ok` would silently under-bill, so this must surface an error.
    const sse =
      chunk({ choices: [{ index: 0, delta: { content: "Hello" }, finish_reason: null }] }) +
      chunk({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }) +
      "data: [DONE]\n\n";
    await expect(
      collect(mapOpenAiStream(Readable.from([Buffer.from(sse)]))),
    ).rejects.toBeInstanceOf(LlmProviderError);
  });

  it("yields no usage event when the stream ends without a usage block", async () => {
    const sse =
      chunk({ choices: [{ index: 0, delta: { content: "Hello" }, finish_reason: null }] }) +
      chunk({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }) +
      "data: [DONE]\n\n";
    const seen: LlmStreamEvent[] = [];
    await expect(
      (async () => {
        try {
          for await (const ev of mapOpenAiStream(Readable.from([Buffer.from(sse)]))) {
            seen.push(ev);
          }
        } catch (err) {
          expect(err).toBeInstanceOf(LlmProviderError);
          throw err;
        }
      })(),
    ).rejects.toBeInstanceOf(LlmProviderError);
    expect(seen.some((e) => e.type === "usage")).toBe(false);
  });

  it("completes normally when usage arrives even without a trailing [DONE]", async () => {
    const sse =
      chunk({ choices: [{ index: 0, delta: { content: "hi" }, finish_reason: "stop" }] }) +
      usageChunk; // no [DONE] — the stream just ends
    const events = await collect(mapOpenAiStream(Readable.from([Buffer.from(sse)])));
    expect(events.at(-1)?.type).toBe("done");
  });

  it("throws on an in-band error object", async () => {
    const sse = `data: ${JSON.stringify({ error: { message: "bad" } })}\n\n`;
    await expect(
      collect(mapOpenAiStream(Readable.from([Buffer.from(sse)]))),
    ).rejects.toBeInstanceOf(LlmProviderError);
  });

  /**
   * Bug-class ledger (sister project): numeric coercion. The usage block is read
   * off the vendor SSE wire — a semi-trusted upstream (any OpenAI-compatible
   * origin the operator wired) — so the counts must be coerced to Numbers at the
   * boundary, not trusted by the `as` cast. A string count reaching the `+`
   * aggregation in the OpenAI codec's `usageBlock` would concatenate
   * (`"12" + 0 + 0` → `"120"`) instead of summing, writing garbage to the app's
   * response and, through `costUsd`, to the ledger.
   */
  it("coerces numeric-string usage counts instead of concatenating them", async () => {
    const sse =
      chunk({ choices: [{ index: 0, delta: { content: "hi" }, finish_reason: "stop" }] }) +
      chunk({ choices: [], usage: { prompt_tokens: "12", completion_tokens: "3" } }) +
      "data: [DONE]\n\n";
    const events = await collect(mapOpenAiStream(Readable.from([Buffer.from(sse)])));
    const done = events.at(-1);
    expect(done?.type === "done" && done.usage).toEqual({
      inputTokens: 12, // not "120" — coerced, then summed downstream
      outputTokens: 3,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
    });
  });

  /**
   * Non-finite counts (a `1e999` overflows to Infinity through JSON.parse; a
   * hostile upstream can also send NaN-bearing junk) must not be able to poison
   * the cost accumulator — `Math.round(Infinity)` into the `costMicroUsd` ledger
   * column fails the INSERT and loses the metering row. Fail closed, like a
   * missing usage block does.
   */
  it("throws on non-finite or non-numeric usage counts", async () => {
    for (const raw of [
      // `1e999` overflows to Infinity inside JSON.parse — the only way a
      // non-finite count can ride the wire (JSON.stringify nulls it).
      '{"prompt_tokens": 1e999, "completion_tokens": 1}',
      '{"prompt_tokens": "abc", "completion_tokens": 1}',
    ]) {
      const sse =
        chunk({ choices: [{ index: 0, delta: { content: "hi" }, finish_reason: "stop" }] }) +
        `data: ${raw}\n\n` +
        "data: [DONE]\n\n";
      await expect(
        collect(mapOpenAiStream(Readable.from([Buffer.from(sse)]))),
      ).rejects.toBeInstanceOf(LlmProviderError);
    }
  });

  it("throws on a negative usage count", async () => {
    const sse =
      chunk({ choices: [{ index: 0, delta: { content: "hi" }, finish_reason: "stop" }] }) +
      chunk({ choices: [], usage: { prompt_tokens: -5, completion_tokens: 1 } }) +
      "data: [DONE]\n\n";
    await expect(
      collect(mapOpenAiStream(Readable.from([Buffer.from(sse)]))),
    ).rejects.toBeInstanceOf(LlmProviderError);
  });
});

describe("RoutingLlmProvider", () => {
  class Recorder implements LlmProvider {
    calls: string[] = [];
    async *stream(r: LlmChatRequest): AsyncIterable<LlmStreamEvent> {
      this.calls.push(r.model);
      yield {
        type: "done",
        stopReason: "end_turn",
        usage: {
          inputTokens: 0,
          outputTokens: 0,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
      };
    }
    async close(): Promise<void> {}
  }

  it("reports support only for families it has an upstream for", () => {
    const both = new RoutingLlmProvider({ anthropic: new Recorder(), openai: new Recorder() });
    expect(both.supports("claude-opus-4-8")).toBe(true);
    expect(both.supports("gpt-4o")).toBe(true);
    expect(both.supports("not-a-model")).toBe(false);

    const anthropicOnly = new RoutingLlmProvider({ anthropic: new Recorder(), openai: null });
    expect(anthropicOnly.supports("claude-opus-4-8")).toBe(true);
    expect(anthropicOnly.supports("gpt-4o")).toBe(false);
  });

  it("dispatches each model to its family upstream", async () => {
    const anthropic = new Recorder();
    const openai = new Recorder();
    const routing = new RoutingLlmProvider({ anthropic, openai });
    await collect(routing.stream(req({ model: "claude-opus-4-8" }), OPTS));
    await collect(routing.stream(req({ model: "gpt-4o" }), OPTS));
    expect(anthropic.calls).toEqual(["claude-opus-4-8"]);
    expect(openai.calls).toEqual(["gpt-4o"]);
  });

  it("throws a 503-shaped error when the family upstream is missing", async () => {
    const routing = new RoutingLlmProvider({ anthropic: new Recorder(), openai: null });
    await expect(collect(routing.stream(req({ model: "gpt-4o" }), OPTS))).rejects.toMatchObject({
      upstreamStatus: 503,
    });
  });

  it("forwards usage events from the inner provider unchanged", async () => {
    const usage: LlmStreamEvent = {
      type: "usage",
      usage: {
        inputTokens: 3,
        outputTokens: 1,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
      },
    };
    const done: LlmStreamEvent = {
      type: "done",
      stopReason: "end_turn",
      usage: {
        inputTokens: 3,
        outputTokens: 1,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
      },
    };
    class UsageThenDone implements LlmProvider {
      async *stream(): AsyncIterable<LlmStreamEvent> {
        yield usage;
        yield done;
      }
      async close(): Promise<void> {}
    }
    const routing = new RoutingLlmProvider({
      anthropic: new UsageThenDone(),
      openai: new Recorder(),
    });
    const events = await collect(routing.stream(req({ model: "claude-opus-4-8" }), OPTS));
    expect(events).toEqual([usage, done]);
  });
});
