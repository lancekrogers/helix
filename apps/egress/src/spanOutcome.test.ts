import { randomBytes, randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import {
  INSTRUCTION_AUDIENCE,
  INSTRUCTION_HEADER,
  INSTRUCTION_JWT_TYP,
  TARGET_HEADER,
} from "@azx-pbc/shared";
import { deriveInstructionKey } from "./instruction.js";
import type { InstructionBurnStore } from "./burn.js";
import { buildApp } from "./app.js";
import type { EgressConfig } from "./config.js";

/**
 * What an egress span says happened, on the paths that are not a clean 200.
 *
 * Two failures the span used to get wrong, both silent:
 *  - an **unhandled throw** recorded `outcome: "ok"`, `upstream.status: 200`
 *    and `client_disconnected: true`, because Fastify's error handler runs
 *    *after* this handler's promise rejects and so nothing had touched `reply`
 *    yet. That triple reads as "a successful 200 the app hung up on";
 *  - a **deliberate refusal** returns normally through `fail()`, so the `catch`
 *    never saw it and the span ended UNSET — 5xx included. Any backend's
 *    built-in error view showed those as successful traces.
 */

let recording: RecordingTelemetry;

beforeAll(() => {
  recording = startRecordingTelemetry();
});
afterEach(() => {
  recording.reset();
});
afterAll(async () => {
  await recording.restore();
});

const key = deriveInstructionKey(randomBytes(32));

function makeApp(burnStore: InstructionBurnStore | null = null): ReturnType<typeof buildApp> {
  const config = {
    limits: { maxBodyBytes: 1024 * 1024, timeoutMs: 5000, llmTimeoutMs: 30_000 },
    allowPrivate: false,
    extraBlockedCidrs: [] as EgressConfig["extraBlockedCidrs"],
    allowInsecureConnection: false,
  } as EgressConfig;
  return buildApp({ config, resolver: null, instructionKey: key, burnStore });
}

async function mint(origin: string): Promise<string> {
  const requestId = randomUUID();
  return new SignJWT({
    appId: "app-1",
    userOid: "user-1",
    capability: "fetch",
    origin,
    requestId,
  })
    .setProtectedHeader({ alg: "HS256", typ: INSTRUCTION_JWT_TYP })
    .setJti(requestId)
    .setAudience(INSTRUCTION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("30s")
    .sign(key);
}

/** The one span each request produces. */
function theSpan(): ReturnType<RecordingTelemetry["spans"]>[number] {
  const spans = recording.spans();
  expect(spans).toHaveLength(1);
  return spans[0]!;
}

describe("an unhandled throw", () => {
  it("is not recorded as a successful, client-abandoned 200", async () => {
    // The burn is awaited inside `runProxy` with no try/catch, so a DB failure
    // there is a genuine unhandled throw on the real code path — not a hook
    // firing outside the span.
    const app = makeApp({
      burn: () => Promise.reject(new Error("burn store unreachable")),
      sweep: () => Promise.resolve(),
      close: () => Promise.resolve(),
    });

    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint("https://api.vendor.test"),
        [TARGET_HEADER]: "https://api.vendor.test/v1",
      },
    });
    expect(res.statusCode).toBe(500);
    await app.close();

    const span = theSpan();
    expect(span.attributes["helix.outcome"]).not.toBe("ok");
    expect(span.attributes["helix.outcome"]).toBe("error");
    // The status the caller sees is written later, by the error handler.
    expect(span.attributes["helix.upstream.status"]).toBeUndefined();
    // Nobody hung up. Naming a condition that did not happen is worse than
    // naming none, on the plane where that distinction changes the diagnosis.
    expect(span.attributes["helix.client_disconnected"]).toBeUndefined();
    expect(span.status.code).toBe(2); // ERROR
  });
});

describe("a deliberate refusal", () => {
  it("marks a 5xx span ERROR even though the handler returned normally", async () => {
    // A secret-bound instruction with no resolver configured: egress fails
    // closed with a 502 through `fail()`, which returns void.
    const app = makeApp();
    const requestId = randomUUID();
    const token = await new SignJWT({
      appId: "app-1",
      userOid: "user-1",
      capability: "fetch",
      origin: "https://api.vendor.test",
      requestId,
      connection: "vendor-key",
    })
      .setProtectedHeader({ alg: "HS256", typ: INSTRUCTION_JWT_TYP })
      .setJti(requestId)
      .setAudience(INSTRUCTION_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime("30s")
      .sign(key);

    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: "https://api.vendor.test/v1",
      },
    });
    expect(res.statusCode).toBeGreaterThanOrEqual(500);
    await app.close();

    const span = theSpan();
    expect(span.status.code).toBe(2); // ERROR
    expect(span.attributes["helix.upstream.status"]).toBe(res.statusCode);
  });

  it("leaves a 4xx span UNSET — a refusal is this service working", async () => {
    const app = makeApp();
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: "not-a-jwt",
        [TARGET_HEADER]: "https://api.vendor.test/v1",
      },
    });
    expect(res.statusCode).toBe(401);
    await app.close();

    const span = theSpan();
    expect(span.status.code).toBe(0); // UNSET
    expect(span.attributes["helix.outcome"]).not.toBe("ok");
  });
});

describe("an unverified caller cannot choose the trace parent", () => {
  const FORGED_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736";
  const FORGED_TRACEPARENT = `00-${FORGED_TRACE}-00f067aa0ba902b7-01`;

  it("ignores traceparent when the instruction does not verify", async () => {
    // ADR-0037 decision 7 permits egress to extract *because* "the caller is
    // the edge, over a hop whose authority already comes from the signed
    // attested instruction". Extraction therefore has to happen after that
    // authority is established, or the justification is not true at the line
    // relying on it.
    const app = makeApp();
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: "forged",
        [TARGET_HEADER]: "https://api.vendor.test/v1",
        traceparent: FORGED_TRACEPARENT,
      },
    });
    expect(res.statusCode).toBe(401);
    await app.close();

    const span = theSpan();
    expect(span.spanContext().traceId).not.toBe(FORGED_TRACE);
    expect(span.parentSpanContext).toBeUndefined();
  });

  it("still records a span for the refusal, so a replay is visible", async () => {
    // Refusals are exactly what an operator wants to see; they are simply not
    // joined to a trace the sender picked.
    const app = makeApp();
    await app.inject({
      method: "POST",
      url: "/proxy",
      headers: { [INSTRUCTION_HEADER]: "forged", [TARGET_HEADER]: "https://api.vendor.test/v1" },
    });
    await app.close();

    expect(theSpan().name).toBe("helix.egress.proxy");
  });

  it("DOES adopt traceparent once the instruction verifies", async () => {
    // The other half — this is the join the whole branch exists to produce.
    const app = makeApp();
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint("https://api.vendor.test"),
        [TARGET_HEADER]: "https://api.vendor.test/v1",
        traceparent: FORGED_TRACEPARENT,
      },
    });
    // Blocked by SSRF/DNS, which is fine — the parent decision happens first.
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    await app.close();

    expect(theSpan().spanContext().traceId).toBe(FORGED_TRACE);
  });
});
