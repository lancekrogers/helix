/**
 * Model pricing — kept as code, applied at read time (architecture §6.1/§8).
 *
 * The `gateway_calls` ledger records token counts, not cost; cost is a pricing
 * decision that shifts independently of the data. We keep the rate table here in
 * `@azx-pbc/shared` and recompute dollars when the portal reads the ledger, so a
 * price change is a map edit + redeploy — and historical figures move to the
 * current rate (an "estimated spend at today's rates" model, not frozen billing).
 *
 * **Cache-aware:** Anthropic bills the three input-token classes at different
 * rates — uncached input at 1x, a cache *write* at 1.25x (5-minute TTL), a cache
 * *read* at 0.1x (0.025x on Fable 5.1). Collapsing them into one number makes spend wrong for
 * cache-heavy apps, so `costUsd` prices each class separately. (Cache counts are
 * 0 until prompt caching is enabled — see apps/edge/src/gateway/provider.ts.)
 */

/**
 * Which upstream serves a model. This is the single source of truth for
 * **routing** as well as pricing: the edge's `RoutingLlmProvider` picks the
 * vendor from this field (`providerForModel`), so the two can never disagree.
 */
export type ModelProvider = "anthropic" | "openai";

/** Per-model base rates in USD per million tokens. */
export interface ModelPrice {
  /** USD per 1M uncached input tokens. */
  inputPerMTok: number;
  /** USD per 1M output tokens. */
  outputPerMTok: number;
  /** Upstream that serves this model (routing + pricing share this fact). */
  provider: ModelProvider;
  /**
   * Cache-**read** rate as a multiple of `inputPerMTok`. Absent ⇒
   * {@link CACHE_READ_MULTIPLIER} (0.1x), which is every model's rate except
   * Claude Fable 5.1's 0.025x. It lives here rather than in a platform-wide
   * constant because a vendor can reprice one model's cache tier alone — as
   * Anthropic did — and a global constant would silently mis-price it.
   */
  cacheReadMultiplier?: number;
  /**
   * OpenAI reasoning models — the o-series and everything from GPT-5 on: they take
   * `max_completion_tokens` (not `max_tokens`, which they reject) and reject a
   * non-default `temperature`. The OpenAI request builder branches on this.
   * Absent ⇒ a pre-GPT-5 chat model that still takes `max_tokens`.
   */
  reasoning?: boolean;
  /**
   * Floor for a reasoning model's `max_completion_tokens`. That budget covers
   * reasoning **and** visible output combined, so a small value can be spent
   * entirely on thinking and return empty (billed) content. The OpenAI builder
   * applies `max(requested ?? floor, floor)` so visible output always has room.
   * Only meaningful with `reasoning: true`.
   */
  minCompletionTokens?: number;
  /**
   * Server-enforced JSON-schema output (ADR-0034). Absent ⇒ the gateway refuses a
   * `responseFormat` request for this model with a 400 rather than letting the
   * upstream reject it. Not uniform across either vendor's line-up, so it is a
   * per-model fact rather than a per-provider one.
   */
  structuredOutputs?: boolean;
  /** Max input tokens the upstream accepts in one request (context window). */
  contextWindowTokens: number;
  /** Max output tokens the upstream can bill in one request (vendor limit). */
  maxOutputTokens: number;
}

/** Output cap Anthropic requests use when the client omits `maxTokens` (edge provider). */
export const ANTHROPIC_DEFAULT_MAX_OUTPUT_TOKENS = 1024;

/**
 * Current catalog rates (USD / 1M tokens). Update here on a pricing change and
 * redeploy. Keys are the exact model ids apps request.
 *
 * This table is also the **authoritative curated-model catalog**: `approval.ts`
 * derives `CURATED_LLM_MODELS` from these keys, so "priced" and "curated" are
 * one set and can't drift. Adding a model to the platform = adding it here with
 * a price; an unpriced model is, by construction, neither curated nor callable
 * (the edge refuses it — see `apps/edge/src/gateway/llm.ts`).
 *
 * The `provider` field also drives model→upstream routing. There is no id-space
 * overlap between the `claude-*` and `gpt-*`/`o*` families, so a flat table is
 * unambiguous.
 *
 * Rates last verified against both vendors' published pricing pages on
 * **2026-09-14**. Both reprice without notice, so re-verify rather than trusting
 * this line's age. The `costUsd` cache classes are Anthropic cache semantics; the
 * OpenAI path reports 0 cache tokens today (`mapOpenAiStream` does not map
 * OpenAI's `cached_tokens`), so the cache multipliers don't apply to `gpt-*`/`o*`
 * — note that OpenAI's own cached-input discount is *not* a flat 0.1x either
 * (gpt-4o is 0.5x, gpt-4.1 0.25x, the current generation 0.1x), so mapping those
 * counts later means pricing them per model, not reusing the constant.
 */
export const MODEL_PRICING: Record<string, ModelPrice> = {
  // Anthropic. NB `structuredOutputs` is deliberately absent on 4-7/4-6/sonnet-4-6:
  // structured outputs are supported on the Fable 5 line, Opus 5, Sonnet 5, Opus 4.8
  // and Haiku 4.5 but not on those three, so the flag is opt-in per model rather
  // than per provider.
  // Fable 5.1 sits above Fable 5 at the same per-token rate, but its cache *reads*
  // bill at 0.025x base input rather than the 0.1x every other model uses — the
  // one reason `cacheReadMultiplier` exists.
  "claude-fable-5-1": {
    inputPerMTok: 10,
    outputPerMTok: 50,
    provider: "anthropic",
    cacheReadMultiplier: 0.025,
    structuredOutputs: true,
    contextWindowTokens: 200_000,
    maxOutputTokens: 64_000,
  },
  "claude-fable-5": {
    inputPerMTok: 10,
    outputPerMTok: 50,
    provider: "anthropic",
    structuredOutputs: true,
    contextWindowTokens: 200_000,
    maxOutputTokens: 64_000,
  },
  "claude-opus-5": {
    inputPerMTok: 5,
    outputPerMTok: 25,
    provider: "anthropic",
    structuredOutputs: true,
    contextWindowTokens: 200_000,
    maxOutputTokens: 64_000,
  },
  // Sonnet 5's $2/$10 was introductory pricing through 2026-08-31; Anthropic made
  // it the standard price and cancelled the scheduled rise to $3/$15. This is now
  // the list rate, so the cost gate no longer over-estimates Sonnet 5 spend.
  "claude-sonnet-5": {
    inputPerMTok: 2,
    outputPerMTok: 10,
    provider: "anthropic",
    structuredOutputs: true,
    contextWindowTokens: 200_000,
    maxOutputTokens: 64_000,
  },
  "claude-opus-4-8": {
    inputPerMTok: 5,
    outputPerMTok: 25,
    provider: "anthropic",
    structuredOutputs: true,
    contextWindowTokens: 200_000,
    maxOutputTokens: 64_000,
  },
  "claude-opus-4-7": {
    inputPerMTok: 5,
    outputPerMTok: 25,
    provider: "anthropic",
    contextWindowTokens: 200_000,
    maxOutputTokens: 8192,
  },
  "claude-opus-4-6": {
    inputPerMTok: 5,
    outputPerMTok: 25,
    provider: "anthropic",
    contextWindowTokens: 200_000,
    maxOutputTokens: 8192,
  },
  "claude-sonnet-4-6": {
    inputPerMTok: 3,
    outputPerMTok: 15,
    provider: "anthropic",
    contextWindowTokens: 200_000,
    maxOutputTokens: 8192,
  },
  // Near-term churn: haiku-4-5's only two Foundry versions both stop serving
  // 2026-10-19 (measured eastus2 2026-09-16). Not a cut — first-party serving
  // is unaffected — but expect the Foundry deployments to need a successor.
  "claude-haiku-4-5": {
    inputPerMTok: 1,
    outputPerMTok: 5,
    provider: "anthropic",
    structuredOutputs: true,
    contextWindowTokens: 200_000,
    maxOutputTokens: 64_000,
  },
  // OpenAI. Every model here resolves to a snapshot new enough for `response_format`
  // json_schema (that floor is `gpt-4o-2024-08-06`), so `structuredOutputs` is set
  // across the board.
  //
  // The current generation — GPT-6 and GPT-5.x — is reasoning models throughout, so
  // `reasoning` is set on all of them. On chat/completions that flag means exactly
  // one thing here: send `max_completion_tokens`, not `max_tokens`. OpenAI has
  // deprecated `max_tokens` outright and reasoning models reject it, so the flag is
  // the forward-compatible setting even where a model would still accept both.
  "gpt-6-astra": {
    inputPerMTok: 10,
    outputPerMTok: 50,
    provider: "openai",
    reasoning: true,
    minCompletionTokens: 25_000,
    structuredOutputs: true,
    contextWindowTokens: 400_000,
    maxOutputTokens: 128_000,
  },
  "gpt-5.6-sol": {
    inputPerMTok: 4,
    outputPerMTok: 20,
    provider: "openai",
    reasoning: true,
    minCompletionTokens: 25_000,
    structuredOutputs: true,
    contextWindowTokens: 400_000,
    maxOutputTokens: 128_000,
  },
  "gpt-5.6-terra": {
    inputPerMTok: 2,
    outputPerMTok: 12,
    provider: "openai",
    reasoning: true,
    minCompletionTokens: 25_000,
    structuredOutputs: true,
    contextWindowTokens: 400_000,
    maxOutputTokens: 128_000,
  },
  "gpt-5.6-luna": {
    inputPerMTok: 0.2,
    outputPerMTok: 1.2,
    provider: "openai",
    reasoning: true,
    minCompletionTokens: 25_000,
    structuredOutputs: true,
    contextWindowTokens: 400_000,
    maxOutputTokens: 128_000,
  },
  "gpt-5.1": {
    inputPerMTok: 1.25,
    outputPerMTok: 10,
    provider: "openai",
    reasoning: true,
    minCompletionTokens: 25_000,
    structuredOutputs: true,
    contextWindowTokens: 400_000,
    maxOutputTokens: 128_000,
  },
  "gpt-5-mini": {
    inputPerMTok: 0.25,
    outputPerMTok: 2,
    provider: "openai",
    reasoning: true,
    minCompletionTokens: 25_000,
    structuredOutputs: true,
    contextWindowTokens: 400_000,
    maxOutputTokens: 128_000,
  },
  "gpt-5-nano": {
    inputPerMTok: 0.05,
    outputPerMTok: 0.4,
    provider: "openai",
    reasoning: true,
    minCompletionTokens: 25_000,
    structuredOutputs: true,
    contextWindowTokens: 400_000,
    maxOutputTokens: 128_000,
  },
  // Previous generations, kept curated so a deployed app's manifest keeps working.
  // Rates re-verified 2026-09-14 and unchanged.
  //
  // `gpt-4o-mini`, `o3` and `o4-mini` were deliberately cut (2026-09-16) rather
  // than retained on that principle: Azure AI Foundry's RP refuses any model
  // whose *default* version is `Deprecating` (`ServiceModelDeprecating`), so
  // they could never ride the one-flag Foundry path, and the current generation
  // covers their price points first-party. A manifest still naming one gets the
  // edge's `model_not_allowed` (no price configured) — the cut is the break.
  "gpt-4o": {
    inputPerMTok: 2.5,
    outputPerMTok: 10,
    provider: "openai",
    structuredOutputs: true,
    contextWindowTokens: 128_000,
    maxOutputTokens: 16_384,
  },
  "gpt-4.1": {
    inputPerMTok: 2,
    outputPerMTok: 8,
    provider: "openai",
    structuredOutputs: true,
    contextWindowTokens: 1_047_576,
    maxOutputTokens: 32_768,
  },
  "gpt-4.1-mini": {
    inputPerMTok: 0.4,
    outputPerMTok: 1.6,
    provider: "openai",
    structuredOutputs: true,
    contextWindowTokens: 1_047_576,
    maxOutputTokens: 32_768,
  },
  "gpt-4.1-nano": {
    inputPerMTok: 0.1,
    outputPerMTok: 0.4,
    provider: "openai",
    structuredOutputs: true,
    contextWindowTokens: 1_047_576,
    maxOutputTokens: 32_768,
  },
};

/**
 * Default cache-read rate: 0.1x the base input rate. A model that bills reads
 * differently overrides it with `ModelPrice.cacheReadMultiplier` (today only
 * Claude Fable 5.1, at 0.025x).
 */
export const CACHE_READ_MULTIPLIER = 0.1;
/** Cache-write tokens bill at 1.25x the base input rate (5-minute TTL — our default). */
export const CACHE_WRITE_MULTIPLIER = 1.25;

/** Default floor for reasoning models' `max_completion_tokens` (see `openAiRequestBody`). */
export const REASONING_MIN_COMPLETION_TOKENS_DEFAULT = 25_000;

/** Look up the rate for a model; undefined when unpriced (UI flags rather than showing $0). */
export function priceForModel(model: string): ModelPrice | undefined {
  return MODEL_PRICING[model];
}

/** Context and output limits for a priced model; undefined when the model is not in the catalog. */
export function limitsForModel(
  model: string,
): Pick<ModelPrice, "contextWindowTokens" | "maxOutputTokens"> | undefined {
  const price = MODEL_PRICING[model];
  if (!price) return undefined;
  return {
    contextWindowTokens: price.contextWindowTokens,
    maxOutputTokens: price.maxOutputTokens,
  };
}

/**
 * Output tokens a cut-call estimate may bill when `maxTokens` is unset — mirrors the
 * gateway's request builders so a hang-up is never charged more than a completed call.
 */
export function outputTokenCapForEstimate(model: string, maxTokens?: number): number {
  const price = priceForModel(model);
  if (!price) return maxTokens ?? 0;
  const limits = limitsForModel(model)!;
  if (price.reasoning) {
    const floor = price.minCompletionTokens ?? REASONING_MIN_COMPLETION_TOKENS_DEFAULT;
    const authorized = Math.max(maxTokens ?? floor, floor);
    return Math.min(authorized, limits.maxOutputTokens);
  }
  if (maxTokens !== undefined) {
    return Math.min(maxTokens, limits.maxOutputTokens);
  }
  if (price.provider === "anthropic") {
    return Math.min(ANTHROPIC_DEFAULT_MAX_OUTPUT_TOKENS, limits.maxOutputTokens);
  }
  if (price.reasoning) {
    const floor = price.minCompletionTokens ?? REASONING_MIN_COMPLETION_TOKENS_DEFAULT;
    return Math.min(floor, limits.maxOutputTokens);
  }
  return limits.maxOutputTokens;
}

/**
 * The upstream that serves a model, or undefined when the model is not in the
 * catalog. The edge routes on this (`RoutingLlmProvider`); an unknown model has
 * no provider and is refused before it can reach any upstream.
 */
export function providerForModel(model: string): ModelProvider | undefined {
  return MODEL_PRICING[model]?.provider;
}

/**
 * Whether `model` can enforce a JSON-schema response (ADR-0034). False for an
 * unknown model, so the gateway fails closed: an uncurated model is refused by
 * the price lookup first, and never reaches an upstream with a `responseFormat`.
 */
export function supportsStructuredOutputs(model: string): boolean {
  return MODEL_PRICING[model]?.structuredOutputs === true;
}

/**
 * Cost in USD for one call's (or one aggregated bucket's) token counts. The
 * three input classes are priced independently; `inputTokens` is the *uncached*
 * remainder (as Anthropic reports it), so there is no double-counting. Unknown
 * models contribute 0 — pair with {@link priceForModel} when you need to flag them.
 */
export function costUsd(input: {
  model: string;
  inputTokens: number;
  outputTokens: number;
  cacheReadInputTokens?: number;
  cacheCreationInputTokens?: number;
}): number {
  const price = MODEL_PRICING[input.model];
  if (!price) return 0;
  const perInputTok = price.inputPerMTok / 1_000_000;
  const perOutputTok = price.outputPerMTok / 1_000_000;
  return (
    input.inputTokens * perInputTok +
    input.outputTokens * perOutputTok +
    (input.cacheReadInputTokens ?? 0) *
      perInputTok *
      (price.cacheReadMultiplier ?? CACHE_READ_MULTIPLIER) +
    (input.cacheCreationInputTokens ?? 0) * perInputTok * CACHE_WRITE_MULTIPLIER
  );
}
