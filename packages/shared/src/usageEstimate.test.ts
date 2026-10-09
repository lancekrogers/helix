import { describe, expect, it } from "vitest";
import { CUT_CHARGE_BASES } from "./telemetry.js";
import { BYTES_PER_TOKEN, estimateCutUsage } from "./usageEstimate.js";

describe("estimateCutUsage", () => {
  it("returns zero counts and estimated basis when there is no measurement and no bytes", () => {
    const result = estimateCutUsage({ measured: undefined, requestBytes: 0, relayedBytes: 0 });
    expect(result.usage.inputTokens).toBe(0);
    expect(result.usage.outputTokens).toBe(0);
    expect(result.basis).toBe("estimated");
  });

  it("estimates from bytes with ceil and BYTES_PER_TOKEN when unmeasured", () => {
    const result = estimateCutUsage({ measured: undefined, requestBytes: 9, relayedBytes: 9 });
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
    });
    const estimatedOutput = Math.ceil(30 / BYTES_PER_TOKEN);
    expect(estimatedOutput).toBeGreaterThan(1);
    expect(result.usage.outputTokens).toBe(estimatedOutput);
    expect(result.basis).toBe("mixed");
  });

  it("estimates multibyte UTF-8 text from byte length", () => {
    const text = "héllo 日本語";
    const bytes = new TextEncoder().encode(text).length;
    const result = estimateCutUsage({
      measured: undefined,
      requestBytes: bytes,
      relayedBytes: 0,
    });
    expect(result.usage.inputTokens).toBe(Math.ceil(bytes / BYTES_PER_TOKEN));
  });

  it("does not overflow on huge byte counts", () => {
    const safe = estimateCutUsage({
      measured: undefined,
      requestBytes: Number.MAX_SAFE_INTEGER,
      relayedBytes: 0,
    });
    expect(Number.isSafeInteger(safe.usage.inputTokens)).toBe(true);
    expect(Number.isFinite(safe.usage.inputTokens)).toBe(true);
    expect(safe.usage.inputTokens).toBe(Math.ceil(Number.MAX_SAFE_INTEGER / BYTES_PER_TOKEN));

    const huge = estimateCutUsage({
      measured: undefined,
      requestBytes: Number.MAX_VALUE,
      relayedBytes: 0,
    });
    expect(Number.isSafeInteger(huge.usage.inputTokens)).toBe(true);
    expect(huge.usage.inputTokens).toBe(Number.MAX_SAFE_INTEGER);
  });

  it("treats non-finite and negative byte counts as zero", () => {
    for (const bad of [-5, NaN, Infinity, -Infinity]) {
      const result = estimateCutUsage({
        measured: undefined,
        requestBytes: bad,
        relayedBytes: bad,
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
    });
    expect(withCache.usage.cacheReadInputTokens).toBe(100);
    expect(withCache.usage.cacheCreationInputTokens).toBe(50);

    const without = estimateCutUsage({ measured: undefined, requestBytes: 0, relayedBytes: 0 });
    expect(without.usage.cacheReadInputTokens).toBe(0);
    expect(without.usage.cacheCreationInputTokens).toBe(0);
  });

  it("returns a basis that is a member of CUT_CHARGE_BASES", () => {
    const cases = [
      estimateCutUsage({ measured: undefined, requestBytes: 0, relayedBytes: 0 }),
      estimateCutUsage({
        measured: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
        requestBytes: 0,
        relayedBytes: 0,
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
    });
    expect(result.basis).toBe("measured");
    expect(result.usage.outputTokens).toBe(0);
  });
});
