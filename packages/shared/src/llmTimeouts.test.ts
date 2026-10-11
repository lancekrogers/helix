import { describe, expect, it } from "vitest";
import {
  DEFAULT_EGRESS_LLM_TIMEOUT_MS,
  DEFAULT_LLM_MAX_CALL_MS,
  EGRESS_LLM_TIMEOUT_MARGIN_MS,
  LLM_EGRESS_HOP_TIMEOUT_MARGIN_MS,
  egressLlmTimeoutMs,
  llmEgressHopTimeoutMs,
} from "./llmTimeouts.js";

describe("LLM timeout derivation", () => {
  it("keeps egress above the edge hop and above the edge deadline", () => {
    const maxCall = DEFAULT_LLM_MAX_CALL_MS;
    expect(llmEgressHopTimeoutMs(maxCall)).toBe(maxCall + LLM_EGRESS_HOP_TIMEOUT_MARGIN_MS);
    expect(egressLlmTimeoutMs(maxCall)).toBe(maxCall + EGRESS_LLM_TIMEOUT_MARGIN_MS);
    expect(EGRESS_LLM_TIMEOUT_MARGIN_MS).toBeGreaterThan(LLM_EGRESS_HOP_TIMEOUT_MARGIN_MS);
    expect(DEFAULT_EGRESS_LLM_TIMEOUT_MS).toBeGreaterThan(maxCall);
  });
});
