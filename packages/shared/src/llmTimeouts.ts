/** Default wall-clock LLM call deadline on the edge (`EDGE_LLM_MAX_CALL_MS`). */
export const DEFAULT_LLM_MAX_CALL_MS = 600_000;

/**
 * Added to `EDGE_LLM_MAX_CALL_MS` for the edge→egress undici hop so the edge's
 * own `AbortSignal.timeout(maxCallMs)` fires before the hop idle timeout.
 */
export const LLM_EGRESS_HOP_TIMEOUT_MARGIN_MS = 60_000;

/**
 * Added to `EDGE_LLM_MAX_CALL_MS` for egress→vendor on `llm` instructions.
 * Must be **greater than** {@link LLM_EGRESS_HOP_TIMEOUT_MARGIN_MS} so egress
 * still has a ceiling if the edge process dies without aborting.
 */
export const EGRESS_LLM_TIMEOUT_MARGIN_MS = 120_000;

/** Ledger `errorDetail` for a cut charge after a hop or egress upstream timeout. */
export const LLM_UPSTREAM_TIMEOUT_DETAIL = "upstream_timeout";

export function llmEgressHopTimeoutMs(maxCallMs: number): number {
  return maxCallMs + LLM_EGRESS_HOP_TIMEOUT_MARGIN_MS;
}

export function egressLlmTimeoutMs(maxCallMs: number): number {
  return maxCallMs + EGRESS_LLM_TIMEOUT_MARGIN_MS;
}

export const DEFAULT_EGRESS_LLM_TIMEOUT_MS = egressLlmTimeoutMs(DEFAULT_LLM_MAX_CALL_MS);
