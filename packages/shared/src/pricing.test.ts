import { describe, expect, it } from "vitest";
import {
  CACHE_READ_MULTIPLIER,
  CACHE_WRITE_MULTIPLIER,
  costUsd,
  MODEL_PRICING,
  outputTokenCapForEstimate,
  priceForModel,
  providerForModel,
  supportsStructuredOutputs,
} from "./pricing.js";

describe("pricing", () => {
  it("prices uncached input + output at the model's base rates", () => {
    // opus-4-8: $5/MTok in, $25/MTok out.
    const cost = costUsd({
      model: "claude-opus-4-8",
      inputTokens: 1_000_000,
      outputTokens: 1_000_000,
    });
    expect(cost).toBeCloseTo(5 + 25, 9);
  });

  it("prices cache reads at 0.1x and cache writes at 1.25x the base input rate", () => {
    const read = costUsd({
      model: "claude-opus-4-8",
      inputTokens: 0,
      outputTokens: 0,
      cacheReadInputTokens: 1_000_000,
    });
    expect(read).toBeCloseTo(5 * CACHE_READ_MULTIPLIER, 9); // $0.50

    const write = costUsd({
      model: "claude-opus-4-8",
      inputTokens: 0,
      outputTokens: 0,
      cacheCreationInputTokens: 1_000_000,
    });
    expect(write).toBeCloseTo(5 * CACHE_WRITE_MULTIPLIER, 9); // $6.25
  });

  it("prices a model's cache reads at its own multiplier, not the platform default", () => {
    // Fable 5.1 bills reads at 0.025x base input; every other model is 0.1x. A
    // single global constant silently over-charged this model by 4x.
    const fable51 = costUsd({
      model: "claude-fable-5-1",
      inputTokens: 0,
      outputTokens: 0,
      cacheReadInputTokens: 1_000_000,
    });
    expect(fable51).toBeCloseTo(10 * 0.025, 9); // $0.25

    // Fable 5, same base rate, no override — falls back to the 0.1x default.
    const fable5 = costUsd({
      model: "claude-fable-5",
      inputTokens: 0,
      outputTokens: 0,
      cacheReadInputTokens: 1_000_000,
    });
    expect(fable5).toBeCloseTo(10 * CACHE_READ_MULTIPLIER, 9); // $1.00
    expect(fable51).toBeLessThan(fable5);

    // The override is cache-read only — it must not touch writes.
    expect(
      costUsd({
        model: "claude-fable-5-1",
        inputTokens: 0,
        outputTokens: 0,
        cacheCreationInputTokens: 1_000_000,
      }),
    ).toBeCloseTo(10 * CACHE_WRITE_MULTIPLIER, 9); // $12.50
  });

  it("treats absent cache counts as zero (no double-counting)", () => {
    const a = costUsd({ model: "claude-haiku-4-5", inputTokens: 500, outputTokens: 500 });
    const b = costUsd({
      model: "claude-haiku-4-5",
      inputTokens: 500,
      outputTokens: 500,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
    });
    expect(a).toBe(b);
  });

  it("contributes 0 for an unpriced model and reports it via priceForModel", () => {
    expect(
      costUsd({ model: "some-future-model", inputTokens: 1_000_000, outputTokens: 1_000_000 }),
    ).toBe(0);
    expect(priceForModel("some-future-model")).toBeUndefined();
    expect(priceForModel("claude-opus-4-8")).toMatchObject({
      inputPerMTok: 5,
      outputPerMTok: 25,
      provider: "anthropic",
      structuredOutputs: true,
      contextWindowTokens: expect.any(Number),
      maxOutputTokens: expect.any(Number),
    });
  });

  it("defines context-window and output limits for every priced model", () => {
    for (const [model, price] of Object.entries(MODEL_PRICING)) {
      expect(price.contextWindowTokens, model).toBeGreaterThan(0);
      expect(price.maxOutputTokens, model).toBeGreaterThan(0);
    }
  });

  it("matches Anthropic default output when maxTokens is unset", () => {
    expect(outputTokenCapForEstimate("claude-fable-5-1")).toBe(1024);
  });
});

describe("supportsStructuredOutputs (ADR-0034)", () => {
  // Pinned explicitly, negatives included: structured output is a per-model fact,
  // and a catalog edit must not silently flip a model on or off.
  const UNSUPPORTED = ["claude-opus-4-7", "claude-opus-4-6", "claude-sonnet-4-6"];

  it("is false for models that cannot enforce a schema", () => {
    for (const model of UNSUPPORTED) {
      expect(priceForModel(model)).toBeDefined(); // still curated & callable
      expect(supportsStructuredOutputs(model)).toBe(false);
    }
  });

  it("is true for every other curated model", () => {
    const rest = Object.keys(MODEL_PRICING).filter((m) => !UNSUPPORTED.includes(m));
    expect(rest.length).toBeGreaterThan(0);
    for (const model of rest) expect(supportsStructuredOutputs(model)).toBe(true);
  });

  it("fails closed for an uncurated model", () => {
    expect(supportsStructuredOutputs("some-future-model")).toBe(false);
  });

  it("curates the current flagship models, which were missing entirely", () => {
    // Without these two, the newest schema-capable Anthropic models weren't
    // priced — so not curated, and not callable at all.
    for (const model of ["claude-opus-5", "claude-sonnet-5"]) {
      expect(priceForModel(model)).toBeDefined();
      expect(supportsStructuredOutputs(model)).toBe(true);
      // `reasoning` means "takes max_completion_tokens", which is an OpenAI-only
      // concern — never set on a `claude-*` model.
      expect(priceForModel(model)?.reasoning).toBeUndefined();
    }
    // Sonnet 5's $2/$10 introductory rate became the standard price on 2026-09-01
    // (the scheduled rise to $3/$15 was cancelled), so this is the list rate now.
    expect(priceForModel("claude-sonnet-5")).toMatchObject({ inputPerMTok: 2, outputPerMTok: 10 });
  });
});

describe("the OpenAI catalog's request shape", () => {
  // `reasoning` decides whether the edge sends `max_completion_tokens` or the
  // deprecated `max_tokens` (apps/edge/src/gateway/provider.ts). A current-generation
  // model that arrives without the flag gets `max_tokens` and is rejected upstream —
  // a 400 on every call to that model, which no other test would catch.
  const TAKES_MAX_TOKENS = ["gpt-4o", "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano"];

  it("marks every model newer than the gpt-4.x line as a reasoning model", () => {
    const openai = Object.entries(MODEL_PRICING).filter(([, p]) => p.provider === "openai");
    expect(openai.length).toBeGreaterThan(TAKES_MAX_TOKENS.length);
    for (const [model, price] of openai) {
      if (TAKES_MAX_TOKENS.includes(model)) {
        expect(price.reasoning).toBeUndefined();
      } else {
        expect(price.reasoning, `${model} must take max_completion_tokens`).toBe(true);
        // A reasoning budget covers thinking *and* visible output, so an unset
        // floor lets a small maxTokens be spent entirely on reasoning.
        expect(price.minCompletionTokens, `${model} needs an output floor`).toBeGreaterThan(0);
      }
    }
  });

  it("never marks a claude-* model as reasoning (that flag is OpenAI-only)", () => {
    for (const [model, price] of Object.entries(MODEL_PRICING)) {
      if (price.provider !== "anthropic") continue;
      expect(price.reasoning, model).toBeUndefined();
      expect(price.minCompletionTokens, model).toBeUndefined();
    }
  });

  it("routes every catalog key to the vendor its id implies", () => {
    for (const [model, price] of Object.entries(MODEL_PRICING)) {
      const expected = model.startsWith("claude-") ? "anthropic" : "openai";
      expect(providerForModel(model), model).toBe(expected);
      expect(price.provider).toBe(expected);
    }
  });
});
