import type { LlmUsage } from "./llm.js";
import { limitsForModel, outputTokenCapForEstimate } from "./pricing.js";
import type { CutChargeBasis } from "./telemetry.js";

/**
 * Bytes per token used when a call ends without a vendor usage count. English averages
 * about 4; 3 over-counts it, which is the safe direction for a budget gate. A heuristic,
 * wrong by tens of percent for non-Latin text, code, or reasoning models whose hidden
 * tokens are billed and never streamed. Tune here.
 */
export const BYTES_PER_TOKEN = 3;

export interface CutUsageEstimate {
  usage: LlmUsage;
  basis: CutChargeBasis;
}

function tokensFromBytes(bytes: number): number {
  if (!Number.isFinite(bytes) || bytes <= 0) return 0;
  return Math.min(Math.ceil(bytes / BYTES_PER_TOKEN), Number.MAX_SAFE_INTEGER);
}

function capEstimatedTokens(tokens: number, cap: number): number {
  if (cap <= 0) return tokens;
  return Math.min(tokens, cap);
}

export function estimateCutUsage(input: {
  /** The last usage event the provider delivered, or undefined if none arrived. */
  measured: LlmUsage | undefined;
  /** UTF-8 length of the system prompt plus every message's content. */
  requestBytes: number;
  /** Sum of the UTF-8 length of every text delta relayed to the app. */
  relayedBytes: number;
  /** Requested model id — caps apply only to byte estimates, not measured vendor counts. */
  model: string;
  /** Client `maxTokens`, when set; used with the catalog output limit for estimates. */
  maxTokens?: number;
}): CutUsageEstimate {
  const { measured } = input;
  const limits = limitsForModel(input.model);
  const contextCap = limits?.contextWindowTokens ?? 0;
  const outputCap = outputTokenCapForEstimate(input.model, input.maxTokens);

  const estimatedInput = capEstimatedTokens(tokensFromBytes(input.requestBytes), contextCap);
  const estimatedOutput = capEstimatedTokens(tokensFromBytes(input.relayedBytes), outputCap);

  const inputTokens = measured ? measured.inputTokens : estimatedInput;
  const outputTokens = Math.max(measured?.outputTokens ?? 0, estimatedOutput);

  const inputMeasured = measured !== undefined;
  const outputMeasured = measured !== undefined && measured.outputTokens >= estimatedOutput;
  const basis: CutChargeBasis =
    inputMeasured && outputMeasured
      ? "measured"
      : !inputMeasured && !outputMeasured
        ? "estimated"
        : "mixed";

  return {
    usage: {
      inputTokens,
      outputTokens,
      cacheReadInputTokens: measured?.cacheReadInputTokens ?? 0,
      cacheCreationInputTokens: measured?.cacheCreationInputTokens ?? 0,
    },
    basis,
  };
}
