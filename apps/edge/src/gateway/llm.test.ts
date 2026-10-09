import { randomUUID } from "node:crypto";
import { request as undiciRequest } from "undici";
import { describe, expect, it } from "vitest";
import { startRecordingTelemetry } from "@azx-pbc/telemetry/testing";
import { ATTR_REASON, INSTR_GATEWAY_ADMISSION_DENIED, SPAN_LLM } from "@azx-pbc/shared/telemetry";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { BYTES_PER_TOKEN, costUsd } from "@azx-pbc/shared";
import { buildApp } from "../app.js";
import { SESSION_COOKIE } from "../auth/cookies.js";
import { hashSessionToken, newSessionToken } from "../auth/sessions.js";
import { testAuthConfig, testEdgeConfig } from "../test/config.js";
import { until, withServer } from "../test/socket.js";
import {
  FakeBlobReader,
  FakeLlmProvider,
  FakeOidcClient,
  FakeRegistry,
  FakeSessionStore,
  FakeUsageStore,
  registryEntry,
} from "../test/fakes.js";
import { LlmProviderError } from "./provider.js";
import { ERROR_DETAIL_MAX } from "./usage.js";
import { secondsUntilNextLocalMidnight } from "./llm.js";

/**
 * The `/_api/llm/chat` gateway (architecture §6.1, project plan §4 M4): authn,
 * cross-app CSRF, the manifest model allowlist, block-new/finish-in-flight
 * quota, streaming relay, and per-call metering. Fakes for the provider and
 * ledger — no network, no DB.
 */

const APP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PREFIX = "apps/a/1/";
const HOST = { host: "demo.local.helix.azxlabs.io" };
const ORIGIN = "https://demo.local.helix.azxlabs.io:8080";
const MODEL = "claude-opus-4-8";

interface LlmEdge {
  app: FastifyInstance;
  sessions: FakeSessionStore;
  provider: FakeLlmProvider;
  usage: FakeUsageStore;
}

function buildLlmEdge(
  opts: {
    llm?: { models: string[]; dollarsPerDay?: number } | null;
    withProvider?: boolean;
    defaultDollarsPerDay?: number;
    platformCeilingDollars?: number;
  } = {},
): LlmEdge {
  const sessions = new FakeSessionStore();
  const provider = new FakeLlmProvider();
  const usage = new FakeUsageStore();
  // Default cap is $1/day (1e6 micro-USD); the burst sub-cap is $1/6.
  const llm = opts.llm === undefined ? { models: [MODEL], dollarsPerDay: 1 } : opts.llm;
  const app = buildApp({
    config: testEdgeConfig({
      auth: testAuthConfig(),
      allowUnauthenticated: false,
      llm: {
        endpoint: "https://api.anthropic.com",
        path: "/v1/messages",
        anthropicVersion: "2023-06-01",
        connection: "anthropic",
        openai: {
          endpoint: "https://api.openai.com",
          path: "/v1/chat/completions",
          connection: "openai",
        },
        defaultDollarsPerDay: opts.defaultDollarsPerDay ?? 50,
        platformDollarsPerDay: opts.platformCeilingDollars ?? 0,
      },
    }),
    registry: new FakeRegistry([
      registryEntry({ appId: APP_ID, slug: "demo", blobPrefix: PREFIX, llm }),
    ]),
    blob: new FakeBlobReader(),
    sessions,
    oidc: new FakeOidcClient(),
    llmProvider: opts.withProvider === false ? null : provider,
    usage: opts.withProvider === false ? null : usage,
  });
  return { app, sessions, provider, usage };
}

async function seedSession(sessions: FakeSessionStore, appId = APP_ID): Promise<string> {
  const id = randomUUID();
  await sessions.createPending({
    id,
    appId,
    user: {
      oid: "oid-alice",
      displayName: "Alice Anders",
      name: null,
      email: null,
      kind: "user",
      groups: [],
    },
    refreshDueAt: new Date(Date.now() + 60_000),
    expiresAt: new Date(Date.now() + 3_600_000),
  });
  const token = newSessionToken();
  await sessions.redeem(id, appId, hashSessionToken(token));
  return token;
}

function chat(
  edge: LlmEdge,
  token: string | null,
  body: unknown,
  opts: { origin?: string | null; host?: string } = {},
): Promise<LightMyRequestResponse> {
  const origin = opts.origin === undefined ? ORIGIN : opts.origin;
  return edge.app.inject({
    method: "POST",
    url: "/_api/llm/chat",
    headers: {
      host: opts.host ?? HOST.host,
      "sec-fetch-mode": "cors",
      "content-type": "application/json",
      ...(origin ? { origin } : {}),
      ...(token ? { cookie: `${SESSION_COOKIE}=${token}` } : {}),
    },
    payload: body as object,
  });
}

const ASK = { model: MODEL, messages: [{ role: "user", content: "hi" }] };

describe("happy paths", () => {
  it("streams deltas + done as SSE and meters the call once", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: true });

    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toContain("text/event-stream");
    expect(res.body).toContain("event: delta");
    expect(res.body).toContain('"text":"Hello"');
    expect(res.body).toContain("event: done");
    expect(res.body).toContain('"stopReason":"end_turn"');

    expect(edge.provider.calls).toHaveLength(1);
    expect(edge.provider.calls[0]?.model).toBe(MODEL);
    expect(edge.usage.records).toHaveLength(1);
    expect(edge.usage.records[0]).toMatchObject({
      appId: APP_ID,
      userOid: "oid-alice",
      userName: null,
      userEmail: null,
      userKind: "user" as const,
      capability: "llm",
      model: MODEL,
      inputTokens: 5,
      outputTokens: 2,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
      // 5 input × $5/Mtok + 2 output × $25/Mtok = 75 micro-USD (opus-4-8).
      costMicroUsd: 75,
      outcome: "ok",
      stopReason: "end_turn",
      errorDetail: null,
    });
    expect(edge.usage.records[0]?.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("meters once with done totals when the provider emits an interim usage event", async () => {
    const edge = buildLlmEdge();
    edge.provider.earlyUsage = {
      inputTokens: 999,
      outputTokens: 0,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
    };
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: true });

    expect(res.statusCode).toBe(200);
    expect(edge.usage.records).toHaveLength(1);
    expect(edge.usage.records[0]).toMatchObject({
      inputTokens: 5,
      outputTokens: 2,
      costMicroUsd: 75,
      outcome: "ok",
    });
  });

  it("returns a single JSON body when stream:false", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: false });

    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toContain("application/json");
    expect(res.json()).toEqual({
      model: MODEL,
      content: "Hello world",
      stopReason: "end_turn",
      usage: {
        inputTokens: 5,
        outputTokens: 2,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
      },
    });
    expect(edge.usage.records[0]?.outcome).toBe("ok");
  });
});

describe("structured output (ADR-0034)", () => {
  const SCHEMA = {
    type: "object",
    properties: { city: { type: "string" } },
    required: ["city"],
    additionalProperties: false,
  };

  it("passes responseFormat through to the provider and streams normally", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    edge.provider.deltas = ['{"city":', '"Paris"}'];
    const res = await chat(edge, token, {
      ...ASK,
      stream: true,
      responseFormat: { type: "json_schema", name: "place", schema: SCHEMA },
    });

    expect(res.statusCode).toBe(200);
    expect(edge.provider.calls[0]?.responseFormat).toEqual({
      type: "json_schema",
      name: "place",
      schema: SCHEMA,
    });
    // The JSON rides the ordinary delta frames — no new event type.
    expect(res.body).toContain("event: delta");
    expect(res.body).toContain("event: done");
  });

  it("returns the JSON as content on the non-streaming path", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    edge.provider.deltas = ['{"city":', '"Paris"}'];
    const res = await chat(edge, token, {
      ...ASK,
      stream: false,
      responseFormat: { type: "json_schema", schema: SCHEMA },
    });

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.json().content)).toEqual({ city: "Paris" });
  });

  it("400s a model that cannot enforce a schema, before any upstream call", async () => {
    const unsupported = "claude-sonnet-4-6";
    const edge = buildLlmEdge({ llm: { models: [unsupported], dollarsPerDay: 1 } });
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, {
      model: unsupported,
      messages: [{ role: "user", content: "hi" }],
      responseFormat: { type: "json_schema", schema: SCHEMA },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("validation_failed");
    expect(edge.provider.calls).toHaveLength(0);
    expect(edge.usage.records).toHaveLength(0);
  });

  it("still serves that model for plain text chat", async () => {
    const unsupported = "claude-sonnet-4-6";
    const edge = buildLlmEdge({ llm: { models: [unsupported], dollarsPerDay: 1 } });
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, {
      model: unsupported,
      messages: [{ role: "user", content: "hi" }],
      stream: false,
    });
    expect(res.statusCode).toBe(200);
  });

  it("400s an oversized schema", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, {
      ...ASK,
      responseFormat: {
        type: "json_schema",
        schema: { type: "object", properties: { a: { description: "x".repeat(40_000) } } },
      },
    });
    expect(res.statusCode).toBe(400);
    expect(edge.provider.calls).toHaveLength(0);
  });
});

describe("authorization", () => {
  it("401s an unauthenticated request and never calls the provider", async () => {
    const edge = buildLlmEdge();
    const res = await chat(edge, null, ASK);
    expect(res.statusCode).toBe(401);
    expect(edge.provider.calls).toHaveLength(0);
  });

  it("403s a disallowed model", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { model: "gpt-5", messages: ASK.messages });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe("model_not_allowed");
    expect(edge.provider.calls).toHaveLength(0);
  });

  it("403s an app with no LLM grant", async () => {
    const edge = buildLlmEdge({ llm: null });
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, ASK);
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe("forbidden");
  });

  it("403s a cross-origin (sibling subdomain) POST — CSRF", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, ASK, {
      origin: "https://evil.local.helix.azxlabs.io:8080",
    });
    expect(res.statusCode).toBe(403);
    expect(edge.provider.calls).toHaveLength(0);
  });

  it("403s an origin-less POST", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, ASK, { origin: null });
    expect(res.statusCode).toBe(403);
  });

  it("503s when no vendor key is configured", async () => {
    const edge = buildLlmEdge({ withProvider: false });
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, ASK);
    expect(res.statusCode).toBe(503);
    expect(res.json().error.code).toBe("capability_unavailable");
  });

  it("404s off app hosts", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, ASK, { host: "auth.local.helix.azxlabs.io" });
    expect(res.statusCode).toBe(404);
  });
});

describe("quota: block-new, finish-in-flight (USD)", () => {
  it("429s a new request once the daily spend cap is reached, and audits the block", async () => {
    const edge = buildLlmEdge();
    edge.usage.spendTodayMicro = 1_000_000; // == $1 cap
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, ASK);

    expect(res.statusCode).toBe(429);
    expect(res.json().error.code).toBe("quota_exceeded");
    expect(edge.provider.calls).toHaveLength(0); // nothing sent upstream
    expect(edge.usage.records).toEqual([
      expect.objectContaining({ outcome: "quota_blocked", costMicroUsd: 0 }),
    ]);
  });

  it("429s rate_limited when the rolling-hour burst cap trips but the day cap has room", async () => {
    const edge = buildLlmEdge();
    // Day cap $1 (1e6); burst cap $1/6 ≈ 166_666. Under the day, over the burst.
    edge.usage.spendTodayMicro = 200_000;
    edge.usage.spendHourMicro = 200_000;
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, ASK);

    expect(res.statusCode).toBe(429);
    expect(res.json().error.code).toBe("rate_limited");
    expect(edge.provider.calls).toHaveLength(0);
    expect(edge.usage.records).toEqual([
      expect.objectContaining({ outcome: "quota_blocked", costMicroUsd: 0 }),
    ]);
  });

  it("sets helix.reason on the llm span for day and burst refusals", async () => {
    const telemetry = startRecordingTelemetry();
    try {
      const dayEdge = buildLlmEdge();
      dayEdge.usage.spendTodayMicro = 1_000_000;
      const dayToken = await seedSession(dayEdge.sessions);
      await chat(dayEdge, dayToken, ASK);
      const daySpan = telemetry.spans().find((s) => s.name === SPAN_LLM);
      expect(daySpan?.attributes[ATTR_REASON]).toBe("app_budget_day");

      telemetry.reset();
      const burstEdge = buildLlmEdge();
      burstEdge.usage.spendTodayMicro = 200_000;
      burstEdge.usage.spendHourMicro = 200_000;
      const burstToken = await seedSession(burstEdge.sessions);
      await chat(burstEdge, burstToken, ASK);
      const burstSpan = telemetry.spans().find((s) => s.name === SPAN_LLM);
      expect(burstSpan?.attributes[ATTR_REASON]).toBe("app_budget_burst");
    } finally {
      await telemetry.restore();
    }
  });

  it("throttles quota_blocked ledger rows after 20 refusals per window but counts every refusal", async () => {
    const telemetry = startRecordingTelemetry();
    try {
      const edge = buildLlmEdge();
      edge.usage.spendTodayMicro = 1_000_000;
      const token = await seedSession(edge.sessions);
      for (let i = 0; i < 25; i += 1) {
        const res = await chat(edge, token, ASK);
        expect(res.statusCode).toBe(429);
        expect(res.json().error.code).toBe("quota_exceeded");
      }
      const blocked = edge.usage.records.filter((r) => r.outcome === "quota_blocked");
      expect(blocked).toHaveLength(20);
      const denied = (await telemetry.metrics()).filter(
        (p) => p.name === INSTR_GATEWAY_ADMISSION_DENIED,
      );
      const totalDenied = denied.reduce((sum, p) => sum + p.value, 0);
      expect(totalDenied).toBe(25);
    } finally {
      await telemetry.restore();
    }
  });

  it("admits an under-cap request and runs it to completion even if it crosses", async () => {
    const edge = buildLlmEdge();
    edge.usage.spendTodayMicro = 999_999; // just under the $1 cap — admitted
    edge.usage.spendHourMicro = 0; // burst has room
    edge.provider.usage = {
      inputTokens: 60,
      outputTokens: 60,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
    }; // pushes well over
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: true });

    expect(res.statusCode).toBe(200);
    // The full stream was delivered — not cut when the budget was crossed.
    expect(res.body).toContain('"text":"Hello"');
    expect(res.body).toContain('"text":" world"');
    expect(res.body).toContain("event: done");
    expect(edge.usage.records[0]).toMatchObject({
      outcome: "ok",
      inputTokens: 60,
      outputTokens: 60,
    });
  });

  it("enforces the install default when the grant omits dollarsPerDay", async () => {
    const unset = buildLlmEdge({ llm: { models: [MODEL] } });
    unset.usage.spendTodayMicro = 50_000_000;
    const token = await seedSession(unset.sessions);
    const atCap = await chat(unset, token, ASK);
    expect(atCap.statusCode).toBe(429);
    expect(atCap.json().error.code).toBe("quota_exceeded");
    expect(unset.provider.calls).toHaveLength(0);

    const burst = buildLlmEdge({ llm: { models: [MODEL] } });
    burst.usage.spendTodayMicro = 1_000_000;
    burst.usage.spendHourMicro = Math.ceil(50_000_000 / 6);
    const burstToken = await seedSession(burst.sessions);
    const overBurst = await chat(burst, burstToken, ASK);
    expect(overBurst.statusCode).toBe(429);
    expect(overBurst.json().error.code).toBe("rate_limited");

    const under = buildLlmEdge({ llm: { models: [MODEL] } });
    under.usage.spendTodayMicro = 49_999_999;
    under.usage.spendHourMicro = 0;
    const underToken = await seedSession(under.sessions);
    const ok = await chat(under, underToken, ASK);
    expect(ok.statusCode).toBe(200);

    const explicit = buildLlmEdge({ llm: { models: [MODEL], dollarsPerDay: 500 } });
    explicit.usage.spendTodayMicro = 400_000_000;
    const explicitToken = await seedSession(explicit.sessions);
    const explicitOk = await chat(explicit, explicitToken, ASK);
    expect(explicitOk.statusCode).toBe(200);

    const noDefault = buildLlmEdge({ llm: { models: [MODEL] }, defaultDollarsPerDay: 0 });
    noDefault.usage.spendTodayMicro = 10_000_000_000;
    const noDefaultToken = await seedSession(noDefault.sessions);
    const unlimited = await chat(noDefault, noDefaultToken, ASK);
    expect(unlimited.statusCode).toBe(200);
  });

  it("403s a model with no configured price before reaching the provider", async () => {
    // Allowlisted but unpriced — the cost gate can't price it, so it's refused.
    const edge = buildLlmEdge({ llm: { models: ["claude-unpriced-x"], dollarsPerDay: 1 } });
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { model: "claude-unpriced-x", messages: ASK.messages });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe("model_not_allowed");
    expect(edge.provider.calls).toHaveLength(0);
  });
});

describe("upstream failure", () => {
  it("502s a streaming failure that happens before the first byte", async () => {
    const edge = buildLlmEdge();
    // `FakeLlmProvider.error` throws before yielding anything, so `start()` has not
    // run and the SSE head is not out — a real status is still possible (ADR-0034).
    edge.provider.error = new Error("boom");
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: true });

    expect(res.statusCode).toBe(502);
    expect(res.headers["content-type"]).toContain("application/json");
    expect(res.json().error.code).toBe("internal");
    expect(edge.usage.records[0]?.outcome).toBe("error");
  });

  it("falls back to an in-band SSE error frame once the head is out", async () => {
    const edge = buildLlmEdge();
    // Throw *after* the first delta, so the 200 + SSE head is already committed and
    // an error frame is the only channel left.
    edge.provider.onDelta = (i) => {
      if (i === 1) throw new Error("boom mid-stream");
    };
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: true });

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("event: delta");
    expect(res.body).toContain("event: error");
    expect(edge.usage.records[0]?.outcome).toBe("error");
  });

  it("502s a non-streaming upstream failure", async () => {
    const edge = buildLlmEdge();
    edge.provider.error = new Error("boom");
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: false });
    expect(res.statusCode).toBe(502);
    expect(edge.usage.records[0]?.outcome).toBe("error");
  });
});

describe("a vendor 400 is the app's fault, not the upstream's (ADR-0034)", () => {
  const SCHEMA = { type: "object", properties: { a: { type: "string" } } };
  /** What EgressLlmProvider throws when the vendor rejects the request body. */
  const vendor400 = (): LlmProviderError =>
    new LlmProviderError(
      'egress llm call failed (400): {"error":{"message":"Invalid schema"}}',
      400,
    );

  it("400s with validation_failed and names the field, non-streaming", async () => {
    const edge = buildLlmEdge();
    edge.provider.error = vendor400();
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, {
      ...ASK,
      stream: false,
      responseFormat: { type: "json_schema", schema: SCHEMA },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("validation_failed");
    expect(res.json().error.message).toContain("responseFormat.schema");
  });

  it("400s on the streaming path too, since nothing has been written yet", async () => {
    const edge = buildLlmEdge();
    edge.provider.error = vendor400();
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, {
      ...ASK,
      stream: true,
      responseFormat: { type: "json_schema", schema: SCHEMA },
    });

    // Without the pre-first-byte status this degraded to 200 + an SSE frame, which
    // would have left the native default path with no actionable signal.
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("validation_failed");
  });

  it("does not blame a schema the app never sent", async () => {
    const edge = buildLlmEdge();
    edge.provider.error = vendor400();
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: false });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.message).not.toContain("responseFormat");
  });

  it("never echoes the vendor's message, which can quote request content", async () => {
    const edge = buildLlmEdge();
    edge.provider.error = vendor400();
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, {
      ...ASK,
      stream: false,
      responseFormat: { type: "json_schema", schema: SCHEMA },
    });

    expect(res.body).not.toContain("Invalid schema");
    expect(res.body).not.toContain("egress llm call failed");
    // ...but the ledger keeps it for the owner (main's cause-walking errorDetailOf).
    expect(edge.usage.records[0]?.errorDetail).toContain("400");
  });

  it("leaves a non-400 upstream failure as 502 internal", async () => {
    const edge = buildLlmEdge();
    edge.provider.error = new LlmProviderError("egress llm call failed (500): boom", 500);
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, {
      ...ASK,
      stream: false,
      responseFormat: { type: "json_schema", schema: SCHEMA },
    });

    expect(res.statusCode).toBe(502);
    expect(res.json().error.code).toBe("internal");
  });
});

describe("an upstream 429 is a throttle, not an outage", () => {
  /** What EgressLlmProvider throws when Foundry answers 429. */
  const vendor429 = (retryAfter?: number): LlmProviderError =>
    new LlmProviderError('egress llm call failed (429): {"error":{"code":"429"}}', 429, retryAfter);

  it("passes through as 429 rate_limited with the vendor's retry-after, non-streaming", async () => {
    const edge = buildLlmEdge();
    edge.provider.error = vendor429(30);
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: false });

    expect(res.statusCode).toBe(429);
    expect(res.headers["retry-after"]).toBe("30");
    expect(res.json().error.code).toBe("rate_limited");
    expect(edge.usage.records[0]?.outcome).toBe("error");
  });

  it("passes through on the streaming path too, since nothing has been written yet", async () => {
    const edge = buildLlmEdge();
    edge.provider.error = vendor429(12);
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: true });

    expect(res.statusCode).toBe(429);
    expect(res.headers["retry-after"]).toBe("12");
    expect(res.headers["content-type"]).toContain("application/json");
    expect(res.json().error.code).toBe("rate_limited");
  });

  it("falls back to a fixed retry-after when the vendor sent none", async () => {
    const edge = buildLlmEdge();
    edge.provider.error = vendor429();
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: false });

    expect(res.statusCode).toBe(429);
    expect(res.headers["retry-after"]).toBe("5");
  });

  it("never echoes the vendor's message", async () => {
    const edge = buildLlmEdge();
    edge.provider.error = vendor429(7);
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: false });

    expect(res.body).not.toContain("egress llm call failed");
    expect(edge.usage.records[0]?.errorDetail).toContain("429");
  });
});

describe("cut and failed calls are charged", () => {
  function cutChargeMicro(
    body: { model: string; messages: { content: string }[]; system?: string },
    usage: { inputTokens: number; outputTokens: number },
  ): number {
    return Math.round(
      costUsd({
        model: body.model,
        inputTokens: usage.inputTokens,
        outputTokens: usage.outputTokens,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
      }) * 1_000_000,
    );
  }

  it("charges an input-byte estimate and blocks the next call when the budget is tight", async () => {
    const system = "x".repeat(3000);
    const body = { ...ASK, stream: false, system };
    const requestBytes =
      Buffer.byteLength(system, "utf8") + Buffer.byteLength(ASK.messages[0]!.content, "utf8");
    const inputTokens = Math.ceil(requestBytes / BYTES_PER_TOKEN);
    const expectedMicro = cutChargeMicro(body, { inputTokens, outputTokens: 0 });
    const edge = buildLlmEdge({
      llm: { models: [MODEL], dollarsPerDay: (expectedMicro - 1) / 1_000_000 },
    });
    const token = await seedSession(edge.sessions);
    edge.provider.deltas = Array.from({ length: 50 }, (_, i) => `d${i}`);
    edge.provider.onDelta = async () => {
      for (let n = 0; n < 500; n++) {
        if (edge.provider.sawAbort) return;
        await new Promise((r) => setTimeout(r, 5));
      }
    };

    function socketHeaders(t: string): Record<string, string> {
      return {
        host: HOST.host,
        "sec-fetch-mode": "cors",
        "content-type": "application/json",
        origin: ORIGIN,
        cookie: `${SESSION_COOKIE}=${t}`,
      };
    }

    await withServer(edge.app, async (base) => {
      const ac = new AbortController();
      const pending = undiciRequest(`${base}/_api/llm/chat`, {
        method: "POST",
        headers: socketHeaders(token),
        body: JSON.stringify(body),
        signal: ac.signal,
      }).catch(() => undefined);
      await until(() => edge.provider.calls.length === 1, "the provider to be called");
      ac.abort();
      await pending;
      await until(() => edge.provider.sawAbort, "the provider signal to abort");
      await until(() => edge.usage.records.length === 1, "the cut row to land");

      expect(edge.usage.records[0]).toMatchObject({
        outcome: "error",
        inputTokens,
        stopReason: null,
      });
      expect(edge.usage.records[0]?.costMicroUsd).toBeGreaterThanOrEqual(expectedMicro);
      expect(edge.usage.records[0]?.errorDetail).toMatch(/;usage=estimated$/);

      const blocked = await undiciRequest(`${base}/_api/llm/chat`, {
        method: "POST",
        headers: socketHeaders(token),
        body: JSON.stringify(ASK),
      });
      expect(blocked.statusCode).toBe(429);
      expect(((await blocked.body.json()) as { error: { code: string } }).error.code).toBe(
        "quota_exceeded",
      );
      expect(edge.usage.records).toHaveLength(2);
      expect(edge.usage.records[1]?.outcome).toBe("quota_blocked");
    });
  });

  it("prefers measured input and estimates relayed output on a mixed hang-up", async () => {
    const edge = buildLlmEdge();
    edge.provider.earlyUsage = {
      inputTokens: 1200,
      outputTokens: 0,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
    };
    edge.provider.deltas = Array.from({ length: 200 }, (_, i) => `d${i}`);
    edge.provider.onDelta = async (i) => {
      if (i > 0) await new Promise((r) => setTimeout(r, 5));
    };
    const token = await seedSession(edge.sessions);
    await withServer(edge.app, async (base) => {
      const res = await undiciRequest(`${base}/_api/llm/chat`, {
        method: "POST",
        headers: {
          host: HOST.host,
          "sec-fetch-mode": "cors",
          "content-type": "application/json",
          origin: ORIGIN,
          cookie: `${SESSION_COOKIE}=${token}`,
        },
        body: JSON.stringify({ ...ASK, stream: true }),
      });
      expect(res.statusCode).toBe(200);
      for await (const chunk of res.body) {
        if (String(chunk).includes("event: delta")) break;
      }
      res.body.destroy();
      await until(() => edge.provider.sawAbort, "the provider signal to abort");
      await until(() => edge.usage.records.length === 1, "the cut row to land");
    });
    const relayedBytes = Buffer.byteLength("d0", "utf8");
    const estimatedOutput = Math.ceil(relayedBytes / BYTES_PER_TOKEN);
    expect(edge.usage.records[0]).toMatchObject({
      inputTokens: 1200,
      stopReason: null,
    });
    expect(edge.usage.records[0]?.outputTokens).toBeGreaterThanOrEqual(estimatedOutput);
    expect(edge.usage.records[0]?.errorDetail).toMatch(/;usage=mixed$/);
    expect(edge.usage.records[0]?.costMicroUsd).toBeGreaterThan(0);
  });

  it("charges a post-200 OpenAI-shaped stream failure and keeps the in-band error frame", async () => {
    const edge = buildLlmEdge();
    const msg = "openai stream ended without a usage block";
    edge.provider.errorAfterDeltas = new LlmProviderError(msg);
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, { ...ASK, stream: true });

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("event: error");
    const row = edge.usage.records[0];
    expect(row).toMatchObject({ outcome: "error", stopReason: null });
    expect(row?.costMicroUsd).toBeGreaterThan(0);
    expect(row?.errorDetail).toMatch(new RegExp(`^${msg};usage=estimated$`));
  });

  it("does not estimate a vendor rejection before the stream starts", async () => {
    for (const status of [429, 400, 500]) {
      const edge = buildLlmEdge();
      edge.provider.error = new LlmProviderError(`vendor ${status}`, status);
      const token = await seedSession(edge.sessions);
      const res = await chat(edge, token, { ...ASK, stream: true });
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      expect(edge.usage.records[0]).toMatchObject({ outcome: "error", costMicroUsd: 0 });
      expect(edge.usage.records[0]?.errorDetail ?? "").not.toMatch(/;usage=/);
    }
  });

  it("keeps the usage marker when the upstream error text is very long", async () => {
    const edge = buildLlmEdge();
    const long = "e".repeat(1000);
    edge.provider.errorAfterDeltas = new LlmProviderError(long);
    const token = await seedSession(edge.sessions);
    await chat(edge, token, { ...ASK, stream: true });
    const detail = edge.usage.records[0]?.errorDetail ?? "";
    expect(detail.length).toBeLessThanOrEqual(ERROR_DETAIL_MAX);
    expect(detail.endsWith(";usage=estimated")).toBe(true);
  });

  it("charges the non-streaming path the same way on a hang-up", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    edge.provider.deltas = Array.from({ length: 50 }, (_, i) => `d${i}`);
    edge.provider.onDelta = async () => {
      for (let n = 0; n < 500; n++) {
        if (edge.provider.sawAbort) return;
        await new Promise((r) => setTimeout(r, 5));
      }
    };
    await withServer(edge.app, async (base) => {
      const ac = new AbortController();
      const pending = undiciRequest(`${base}/_api/llm/chat`, {
        method: "POST",
        headers: {
          host: HOST.host,
          "sec-fetch-mode": "cors",
          "content-type": "application/json",
          origin: ORIGIN,
          cookie: `${SESSION_COOKIE}=${token}`,
        },
        body: JSON.stringify({ ...ASK, stream: false }),
        signal: ac.signal,
      }).catch(() => undefined);
      await until(() => edge.provider.calls.length === 1, "the provider to be called");
      ac.abort();
      await pending;
      await until(() => edge.provider.sawAbort, "the provider signal to abort");
      await until(() => edge.usage.records.length === 1, "the cut row to land");
    });
    expect(String(edge.usage.records[0]?.errorDetail)).toMatch(/^client_disconnected;usage=/);
    expect(edge.usage.records[0]?.costMicroUsd).toBeGreaterThan(0);
    expect(edge.usage.records[0]?.stopReason).toBeNull();
  });
});

/**
 * Real-socket coverage for client disconnect. The rest of this file drives the
 * app through `app.inject()`, which cannot express a client hanging up — and
 * this route's disconnect handling was broken for exactly as long as nothing
 * tested it over a socket.
 */
describe("/_api/llm/chat over a real socket", () => {
  function headers(token: string): Record<string, string> {
    return {
      host: HOST.host,
      "sec-fetch-mode": "cors",
      "content-type": "application/json",
      origin: ORIGIN,
      cookie: `${SESSION_COOKIE}=${token}`,
    };
  }

  it("aborts the upstream when the client hangs up mid-stream", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    // Long enough to still be streaming when the client goes; the per-delta
    // pause keeps the stream open without the test sleeping on a fixed budget.
    edge.provider.deltas = Array.from({ length: 200 }, (_, i) => `d${i}`);
    edge.provider.onDelta = async (i) => {
      if (i > 0) await new Promise((r) => setTimeout(r, 5));
    };
    await withServer(edge.app, async (base) => {
      const res = await undiciRequest(`${base}/_api/llm/chat`, {
        method: "POST",
        headers: headers(token),
        body: JSON.stringify({ ...ASK, stream: true }),
      });
      expect(res.statusCode).toBe(200);
      for await (const chunk of res.body) {
        // Hang up as soon as the stream is demonstrably flowing.
        if (String(chunk).includes("event: delta")) break;
      }
      res.body.destroy();
      await until(() => edge.provider.sawAbort, "the provider signal to abort");
      // The ledger write trails the abort — wait for the row itself, not just
      // the signal, or the assertions below race the handler's catch.
      await until(() => edge.usage.records.length === 1, "the call to be metered");
    });
    // Metered once, and marked as the app leaving rather than a vendor failure.
    expect(edge.usage.records).toHaveLength(1);
    expect(edge.usage.records[0]?.outcome).toBe("error");
    expect(edge.usage.records[0]?.errorDetail).toMatch(
      /^client_disconnected;usage=(measured|estimated|mixed)$/,
    );
    expect(edge.usage.records[0]?.costMicroUsd).toBeGreaterThan(0);
    expect(edge.usage.records[0]?.stopReason).toBeNull();
  });

  it("aborts a non-streaming call when the client hangs up", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    edge.provider.deltas = Array.from({ length: 200 }, (_, i) => `d${i}`);
    edge.provider.onDelta = async (i) => {
      if (i > 0) await new Promise((r) => setTimeout(r, 5));
    };
    await withServer(edge.app, async (base) => {
      const ac = new AbortController();
      const pending = undiciRequest(`${base}/_api/llm/chat`, {
        method: "POST",
        headers: headers(token),
        body: JSON.stringify({ ...ASK, stream: false }),
        signal: ac.signal,
      }).catch(() => undefined);
      await until(() => edge.provider.calls.length === 1, "the provider to be called");
      ac.abort();
      await pending;
      await until(() => edge.provider.sawAbort, "the provider signal to abort");
      await until(() => edge.usage.records.length === 1, "the call to be metered");
    });
    expect(edge.usage.records).toHaveLength(1);
    expect(edge.usage.records[0]?.outcome).toBe("error");
    expect(edge.usage.records[0]?.errorDetail).toMatch(
      /^client_disconnected;usage=(measured|estimated|mixed)$/,
    );
    expect(edge.usage.records[0]?.costMicroUsd).toBeGreaterThan(0);
    expect(edge.usage.records[0]?.stopReason).toBeNull();
  });

  it("streams a normal completion unchanged over a socket", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    await withServer(edge.app, async (base) => {
      const res = await undiciRequest(`${base}/_api/llm/chat`, {
        method: "POST",
        headers: headers(token),
        body: JSON.stringify({ ...ASK, stream: true }),
      });
      expect(res.statusCode).toBe(200);
      const body = await res.body.text();
      expect(body).toContain("event: delta");
      expect(body).toContain("event: done");
    });
    expect(edge.provider.sawAbort).toBe(false); // finishing is not a disconnect
    expect(edge.usage.records).toHaveLength(1);
    expect(edge.usage.records[0]?.outcome).toBe("ok");
  });

  it("completes a non-streaming call unchanged over a socket", async () => {
    const edge = buildLlmEdge();
    const token = await seedSession(edge.sessions);
    await withServer(edge.app, async (base) => {
      const res = await undiciRequest(`${base}/_api/llm/chat`, {
        method: "POST",
        headers: headers(token),
        body: JSON.stringify({ ...ASK, stream: false }),
      });
      expect(res.statusCode).toBe(200);
      expect((await res.body.json()) as { content: string }).toMatchObject({
        content: "Hello world",
      });
    });
    expect(edge.provider.sawAbort).toBe(false);
    expect(edge.usage.records[0]?.outcome).toBe("ok");
  });
});

describe("secondsUntilNextLocalMidnight", () => {
  it("returns seconds until local midnight for a mid-day instant", () => {
    const now = new Date(2026, 5, 15, 12, 0, 0);
    expect(secondsUntilNextLocalMidnight(now)).toBe(43_200);
  });

  it("returns at least 1 second just before local midnight", () => {
    const now = new Date(2026, 5, 15, 23, 59, 59, 500);
    expect(secondsUntilNextLocalMidnight(now)).toBe(1);
  });
});

describe("platform ceiling", () => {
  it("503s at the ceiling with retry-after and a throttled denial row", async () => {
    const telemetry = startRecordingTelemetry();
    try {
      const edge = buildLlmEdge({
        llm: { models: [MODEL], dollarsPerDay: 10 },
        platformCeilingDollars: 1,
      });
      edge.usage.spendTodayMicro = 0;
      edge.usage.platformSpendTodayMicro = 1_000_000;
      const token = await seedSession(edge.sessions);
      const res = await chat(edge, token, ASK);
      expect(res.statusCode).toBe(503);
      expect(res.json().error.code).toBe("capability_unavailable");
      expect(res.headers["retry-after"]).toBeDefined();
      const retryAfter = Number(res.headers["retry-after"]);
      expect(retryAfter).toBeGreaterThanOrEqual(1);
      expect(retryAfter).toBeLessThanOrEqual(86_400);
      expect(edge.provider.calls).toHaveLength(0);
      expect(edge.usage.records).toEqual([
        expect.objectContaining({
          outcome: "quota_blocked",
          errorDetail: "platform_ceiling",
        }),
      ]);
    } finally {
      await telemetry.restore();
    }
  });

  it("serves when platform spend is below the ceiling", async () => {
    const edge = buildLlmEdge({
      llm: { models: [MODEL], dollarsPerDay: 10 },
      platformCeilingDollars: 2,
    });
    edge.usage.platformSpendTodayMicro = 1_000_000;
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, ASK);
    expect(res.statusCode).toBe(200);
  });

  it("ignores the ceiling when it is disabled", async () => {
    const edge = buildLlmEdge({
      llm: { models: [MODEL], dollarsPerDay: 10 },
      platformCeilingDollars: 0,
    });
    edge.usage.platformSpendTodayMicro = 9_000_000;
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, ASK);
    expect(res.statusCode).toBe(200);
  });

  it("prefers the per-app 429 when both app and platform are over budget", async () => {
    const edge = buildLlmEdge({
      llm: { models: [MODEL], dollarsPerDay: 1 },
      platformCeilingDollars: 1,
    });
    edge.usage.spendTodayMicro = 1_000_000;
    edge.usage.platformSpendTodayMicro = 1_000_000;
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, ASK);
    expect(res.statusCode).toBe(429);
    expect(res.json().error.code).toBe("quota_exceeded");
  });

  it("throttles platform_ceiling ledger rows but counts every admission denial", async () => {
    const telemetry = startRecordingTelemetry();
    try {
      const edge = buildLlmEdge({
        llm: { models: [MODEL], dollarsPerDay: 10 },
        platformCeilingDollars: 1,
      });
      edge.usage.platformSpendTodayMicro = 1_000_000;
      const token = await seedSession(edge.sessions);
      for (let i = 0; i < 25; i += 1) {
        const res = await chat(edge, token, ASK);
        expect(res.statusCode).toBe(503);
      }
      const blocked = edge.usage.records.filter((r) => r.outcome === "quota_blocked");
      expect(blocked).toHaveLength(20);
      const denied = (await telemetry.metrics()).filter(
        (p) =>
          p.name === INSTR_GATEWAY_ADMISSION_DENIED &&
          p.attributes["helix.reason"] === "platform_ceiling",
      );
      const totalDenied = denied.reduce((sum, p) => sum + p.value, 0);
      expect(totalDenied).toBe(25);
    } finally {
      await telemetry.restore();
    }
  });

  it("503s with retry-after 5 when the platform read fails", async () => {
    const edge = buildLlmEdge({
      llm: { models: [MODEL], dollarsPerDay: 10 },
      platformCeilingDollars: 1,
    });
    edge.usage.platformReadError = new Error("db down");
    const token = await seedSession(edge.sessions);
    const res = await chat(edge, token, ASK);
    expect(res.statusCode).toBe(503);
    expect(res.json().error.code).toBe("capability_unavailable");
    expect(res.headers["retry-after"]).toBe("5");
    expect(edge.provider.calls).toHaveLength(0);
    expect(edge.usage.records).toHaveLength(0);
  });

  it("counts a cut-stream charge toward the platform sum", async () => {
    const system = "x".repeat(3000);
    const body = { ...ASK, stream: false, system };
    const requestBytes =
      Buffer.byteLength(system, "utf8") + Buffer.byteLength(ASK.messages[0]!.content, "utf8");
    const inputTokens = Math.ceil(requestBytes / BYTES_PER_TOKEN);
    const expectedMicro = Math.round(
      costUsd({
        model: body.model,
        inputTokens,
        outputTokens: 0,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
      }) * 1_000_000,
    );
    const edge = buildLlmEdge({
      llm: { models: [MODEL], dollarsPerDay: 100 },
      platformCeilingDollars: expectedMicro / 1_000_000,
    });
    const token = await seedSession(edge.sessions);
    edge.provider.deltas = Array.from({ length: 50 }, (_, i) => `d${i}`);
    edge.provider.onDelta = async () => {
      await new Promise((r) => setTimeout(r, 5));
    };
    await withServer(edge.app, async (base) => {
      const ac = new AbortController();
      const pending = undiciRequest(`${base}/_api/llm/chat`, {
        method: "POST",
        headers: {
          host: HOST.host,
          "sec-fetch-mode": "cors",
          "content-type": "application/json",
          origin: ORIGIN,
          cookie: `${SESSION_COOKIE}=${token}`,
        },
        body: JSON.stringify(body),
        signal: ac.signal,
      }).catch(() => undefined);
      await until(() => edge.provider.calls.length === 1, "provider called");
      ac.abort();
      await pending;
      await until(() => edge.usage.records.length === 1, "cut row");
      const blocked = await undiciRequest(`${base}/_api/llm/chat`, {
        method: "POST",
        headers: {
          host: HOST.host,
          "sec-fetch-mode": "cors",
          "content-type": "application/json",
          origin: ORIGIN,
          cookie: `${SESSION_COOKIE}=${token}`,
        },
        body: JSON.stringify(ASK),
      });
      expect(blocked.statusCode).toBe(503);
      expect(((await blocked.body.json()) as { error: { code: string } }).error.code).toBe(
        "capability_unavailable",
      );
    });
    expect(edge.usage.records[0]?.costMicroUsd).toBeGreaterThanOrEqual(expectedMicro);
  });
});
