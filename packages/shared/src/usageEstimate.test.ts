import { describe, expect, it } from "vitest";
import { costUsd, limitsForModel, outputTokenCapForEstimate } from "./pricing.js";
import { CUT_CHARGE_BASES } from "./telemetry.js";
import { BYTES_PER_TOKEN, estimateCutUsage } from "./usageEstimate.js";

const MODEL = "claude-fable-5-1";

describe("estimateCutUsage", () => {
  it("returns zero counts and estimated basis when there is no measurement and no bytes", () => {
    const result = estimateCutUsage({
      measured: undefined,
      requestBytes: 0,
      relayedBytes: 0,
      model: MODEL,
    });
    expect(result.usage.inputTokens).toBe(0);
    expect(result.usage.outputTokens).toBe(0);
    expect(result.basis).toBe("estimated");
  });

  it("estimates from bytes with ceil and BYTES_PER_TOKEN when unmeasured", () => {
    const result = estimateCutUsage({
      measured: undefined,
      requestBytes: 9,
      relayedBytes: 9,
      model: MODEL,
    });
    expect(result.usage.inputTokens).toBe(3);
    expect(result.usage.outputTokens).toBe(3);
    expect(result.basis).toBe("estimated");
  });

  it("uses measured input and max(measured, estimated) for output", () => {
    const estimatedOutput = Math.ceil(3 / BYTES_PER_TOKEN);
    const result = estimateCutUsage({
      measured: {
        inputTokens: 1200,
        outputTokens: 1,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
      },
      requestBytes: 9999,
      relayedBytes: 3,
      model: MODEL,
    });
    expect(result.usage.inputTokens).toBe(1200);
    expect(result.usage.outputTokens).toBe(Math.max(1, estimatedOutput));
  });

  it("uses measured output when it exceeds the byte estimate and basis is measured", () => {
    const result = estimateCutUsage({
      measured: {
        inputTokens: 500,
        outputTokens: 100,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
      },
      requestBytes: 500,
      relayedBytes: 3,
      model: MODEL,
    });
    expect(result.usage.outputTokens).toBe(100);
    expect(result.basis).toBe("measured");
  });

  it("uses byte estimate when measured output lags (Anthropic-style) and basis is mixed", () => {
    const result = estimateCutUsage({
      measured: {
        inputTokens: 800,
        outputTokens: 1,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
      },
      requestBytes: 800,
      relayedBytes: 30,
      model: MODEL,
    });
    const estimatedOutput = Math.ceil(30 / BYTES_PER_TOKEN);
    expect(estimatedOutput).toBeGreaterThan(1);
    expect(result.usage.outputTokens).toBe(estimatedOutput);
    expect(result.basis).toBe("mixed");
  });

  it("does not clamp a reasoning model's relayed output to a maxTokens below the floor", () => {
    const model = "gpt-5-nano";
    const floor = outputTokenCapForEstimate(model, 1);
    expect(floor).toBeGreaterThan(1);
    const relayedBytes = 3_000;
    const result = estimateCutUsage({
      measured: undefined,
      requestBytes: 30,
      relayedBytes,
      model,
      maxTokens: 1,
    });
    // The vendor request was authorized for the floor, not for maxTokens: 1, so
    // the estimate follows the bytes that were relayed, up to the floor.
    expect(result.usage.outputTokens).toBe(Math.ceil(relayedBytes / 3));
    expect(result.usage.outputTokens).toBeLessThanOrEqual(floor);
  });

  it("caps a reasoning model's relayed output at the floor when maxTokens is below it", () => {
    const model = "gpt-5-nano";
    const floor = outputTokenCapForEstimate(model, 1);
    const result = estimateCutUsage({
      measured: undefined,
      requestBytes: 30,
      relayedBytes: floor * 3 * 10,
      model,
      maxTokens: 1,
    });
    expect(result.usage.outputTokens).toBe(floor);
  });

  it("estimates no output for a reasoning model when nothing was relayed", () => {
    // A cut with nothing relayed is charged its input estimate only. Billing the
    // floor here would let an instant hang-up record a full completion budget.
    const result = estimateCutUsage({
      measured: undefined,
      requestBytes: 30,
      relayedBytes: 0,
      model: "gpt-5-nano",
      maxTokens: 1,
    });
    expect(result.usage.outputTokens).toBe(0);
    expect(result.usage.inputTokens).toBeGreaterThan(0);
  });

  it("estimates multibyte UTF-8 text from byte length", () => {
    const text = "héllo 日本語";
    const bytes = new TextEncoder().encode(text).length;
    const result = estimateCutUsage({
      measured: undefined,
      requestBytes: bytes,
      relayedBytes: 0,
      model: MODEL,
    });
    expect(result.usage.inputTokens).toBe(Math.ceil(bytes / BYTES_PER_TOKEN));
  });

  it("caps unmeasured input at the model context window", () => {
    const limits = limitsForModel(MODEL)!;
    const oneMiB = 1024 * 1024;
    const result = estimateCutUsage({
      measured: undefined,
      requestBytes: oneMiB,
      relayedBytes: 0,
      model: MODEL,
    });
    expect(result.usage.inputTokens).toBe(limits.contextWindowTokens);
    const maxInputCost = costUsd({
      model: MODEL,
      inputTokens: limits.contextWindowTokens,
      outputTokens: 0,
    });
    const charged = costUsd({
      model: MODEL,
      inputTokens: result.usage.inputTokens,
      outputTokens: result.usage.outputTokens,
    });
    expect(charged).toBeLessThanOrEqual(maxInputCost);
    expect(Math.ceil(oneMiB / BYTES_PER_TOKEN)).toBeGreaterThan(limits.contextWindowTokens);
  });

  it("keeps measured input above the context-window cap", () => {
    const limits = limitsForModel(MODEL)!;
    const above = limits.contextWindowTokens + 50_000;
    const result = estimateCutUsage({
      measured: {
        inputTokens: above,
        outputTokens: 0,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
      },
      requestBytes: 1024 * 1024,
      relayedBytes: 0,
      model: MODEL,
    });
    expect(result.usage.inputTokens).toBe(above);
  });

  it("does not overflow on huge byte counts — estimates cap at the context window", () => {
    const limits = limitsForModel(MODEL)!;
    const safe = estimateCutUsage({
      measured: undefined,
      requestBytes: Number.MAX_SAFE_INTEGER,
      relayedBytes: 0,
      model: MODEL,
    });
    expect(safe.usage.inputTokens).toBe(limits.contextWindowTokens);

    const huge = estimateCutUsage({
      measured: undefined,
      requestBytes: Number.MAX_VALUE,
      relayedBytes: 0,
      model: MODEL,
    });
    expect(huge.usage.inputTokens).toBe(limits.contextWindowTokens);
  });

  it("treats non-finite and negative byte counts as zero", () => {
    for (const bad of [-5, NaN, Infinity, -Infinity]) {
      const result = estimateCutUsage({
        measured: undefined,
        requestBytes: bad,
        relayedBytes: bad,
        model: MODEL,
      });
      expect(result.usage.inputTokens).toBeGreaterThanOrEqual(0);
      expect(result.usage.outputTokens).toBeGreaterThanOrEqual(0);
      expect(Number.isNaN(result.usage.inputTokens)).toBe(false);
      expect(Number.isNaN(result.usage.outputTokens)).toBe(false);
      expect(result.usage.inputTokens).toBe(0);
      expect(result.usage.outputTokens).toBe(0);
    }
  });

  it("ceil fractional byte counts to whole tokens", () => {
    const result = estimateCutUsage({
      measured: undefined,
      requestBytes: 10.4,
      relayedBytes: 0,
      model: MODEL,
    });
    expect(result.usage.inputTokens).toBe(Math.ceil(10.4 / BYTES_PER_TOKEN));
    expect(Number.isInteger(result.usage.inputTokens)).toBe(true);
  });

  it("carries cache counts from measured usage and zero otherwise", () => {
    const withCache = estimateCutUsage({
      measured: {
        inputTokens: 10,
        outputTokens: 10,
        cacheReadInputTokens: 100,
        cacheCreationInputTokens: 50,
      },
      requestBytes: 0,
      relayedBytes: 0,
      model: MODEL,
    });
    expect(withCache.usage.cacheReadInputTokens).toBe(100);
    expect(withCache.usage.cacheCreationInputTokens).toBe(50);

    const without = estimateCutUsage({
      measured: undefined,
      requestBytes: 0,
      relayedBytes: 0,
      model: MODEL,
    });
    expect(without.usage.cacheReadInputTokens).toBe(0);
    expect(without.usage.cacheCreationInputTokens).toBe(0);
  });

  it("returns a basis that is a member of CUT_CHARGE_BASES", () => {
    const cases = [
      estimateCutUsage({ measured: undefined, requestBytes: 0, relayedBytes: 0, model: MODEL }),
      estimateCutUsage({
        measured: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
        requestBytes: 0,
        relayedBytes: 0,
        model: MODEL,
      }),
      estimateCutUsage({
        measured: {
          inputTokens: 1,
          outputTokens: 0,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
        requestBytes: 0,
        relayedBytes: 9,
        model: MODEL,
      }),
    ];
    for (const { basis } of cases) {
      expect(CUT_CHARGE_BASES).toContain(basis);
    }
  });

  it("treats measured output zero with no relayed bytes as measured basis", () => {
    const result = estimateCutUsage({
      measured: {
        inputTokens: 100,
        outputTokens: 0,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
      },
      requestBytes: 100,
      relayedBytes: 0,
      model: MODEL,
    });
    expect(result.basis).toBe("measured");
    expect(result.usage.outputTokens).toBe(0);
  });
});
