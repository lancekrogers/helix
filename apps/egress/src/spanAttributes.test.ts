import { randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { SignJWT } from "jose";
import { request as undiciRequest } from "undici";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import {
  INSTRUCTION_AUDIENCE,
  INSTRUCTION_HEADER,
  INSTRUCTION_JWT_TYP,
  METHOD_HEADER,
  TARGET_HEADER,
} from "@azx-pbc/shared";
import {
  ATTR_CLIENT_DISCONNECTED,
  SPAN_EGRESS_PROXY,
  TARGET_PATH_MAX,
} from "@azx-pbc/shared/telemetry";
import { buildApp } from "./app.js";
import type { EgressConfig } from "./config.js";
import { deriveInstructionKey } from "./instruction.js";
import { EGRESS_SPAN_ATTRS, egressSpanAttributes } from "./spanAttributes.js";
import { tracer } from "./telemetry.js";

const instructionKey = deriveInstructionKey(randomBytes(32));

/**
 * ADR-0037 decision 6, egress half: "Egress attributes are a hardcoded
 * allowlist, not an exclusion list. […] Never record request or response
 * headers there: the injected credential *is* a header."
 *
 * This is the plane holding plaintext connection secrets, so these assertions
 * are the mechanical half of a rule the ADR's own consequences say will
 * otherwise decay one span at a time.
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

const SECRET = "sk-PLANTED-CONNECTION-SECRET";
const BEARER = `Bearer ${SECRET}`;

describe("egressSpanAttributes", () => {
  it("drops anything not on the allowlist", () => {
    const attrs = egressSpanAttributes({
      "helix.app_id": "app-1",
      // Every one of these is a plausible thing to reach for, and each is a leak.
      authorization: BEARER,
      "http.request.header.authorization": BEARER,
      "x-api-key": SECRET,
      "url.full": `https://api.vendor.test/v1?api_key=${SECRET}`,
      "helix.response.body": SECRET,
    } as Parameters<typeof egressSpanAttributes>[0]);

    expect(Object.keys(attrs)).toEqual(["helix.app_id"]);
    expect(JSON.stringify(attrs)).not.toContain(SECRET);
  });

  it("names no header, in either direction", () => {
    // Not "no header values" — no header NAMES either. The `header` recipe's
    // name and `hmac-timestamp`'s signature header names are per-connection
    // configuration, and naming them narrows the search for the value.
    for (const key of EGRESS_SPAN_ATTRS) {
      expect(key).not.toMatch(/header/i);
      expect(key).not.toMatch(/authorization|cookie|api[-_]?key|token|secret/i);
    }
  });

  it("carries no whole-URL attribute", () => {
    for (const key of EGRESS_SPAN_ATTRS) {
      expect(["url.full", "http.url", "http.target", "url.query"]).not.toContain(key);
    }
  });

  it("drops undefined rather than recording it", () => {
    // An absent connection must read as absent, not as the string "undefined".
    const attrs = egressSpanAttributes({
      "helix.app_id": "app-1",
      "helix.connection": undefined,
    });
    expect("helix.connection" in attrs).toBe(false);
  });

  it("caps the target path to the same bound the edge uses", () => {
    // `instruction.path` is `z.string().optional()` — no length bound — while
    // the edge caps the identical value for its ledger column and its own span.
    // Recording one value at two lengths is exactly what the edge's comment
    // exists to prevent, and the path is attacker-controlled on a retained
    // backend.
    const long = `/${"a".repeat(TARGET_PATH_MAX * 2)}`;
    const attrs = egressSpanAttributes({ "helix.target.path": long });
    const recorded = attrs["helix.target.path"] as string;

    expect(recorded.length).toBeLessThanOrEqual(TARGET_PATH_MAX + 1); // + the ellipsis
    expect(recorded.endsWith("…")).toBe(true);
  });

  it("leaves a short path untouched", () => {
    const attrs = egressSpanAttributes({ "helix.target.path": "/v1/charges" });
    expect(attrs["helix.target.path"]).toBe("/v1/charges");
  });

  it("keeps enough to diagnose an outbound failure", () => {
    // The allowlist has to be useful, not just safe. An operator debugging a
    // 502 needs to know which app, which origin, which connection and what the
    // upstream said.
    const attrs = egressSpanAttributes({
      "helix.app_id": "app-1",
      "helix.target.origin": "https://api.vendor.test",
      "helix.target.path": "/v1/charges",
      "helix.connection": "stripe-live",
      "helix.upstream.status": 502,
      "helix.outcome": "error",
    });
    expect(Object.keys(attrs)).toHaveLength(6);
  });

  it("carries the delegated dimensions and nothing credential-shaped", () => {
    // The delegated call path widens the VALUE set of helix.credential_source
    // with `delegated` and rides helix.provider_ref — both allowlisted keys,
    // neither a header name nor credential material. The token itself has no
    // key it could ride on, which is the point: even a caller that tries to
    // record one under a plausible name loses it here.
    const attrs = egressSpanAttributes({
      "helix.credential_source": "delegated",
      "helix.provider_ref": "asana",
      "helix.outcome": "connection_required",
      // Plausible credential-shaped keys a delegated path might reach for.
      "helix.access_token": "planted-delegated-token",
      "helix.token": "planted-delegated-token",
      "helix.refresh_token": "planted-delegated-token",
      authorization: "Bearer planted-delegated-token",
    } as Parameters<typeof egressSpanAttributes>[0]);
    expect(attrs["helix.credential_source"]).toBe("delegated");
    expect(attrs["helix.provider_ref"]).toBe("asana");
    expect(Object.keys(attrs)).toHaveLength(3);
    expect(JSON.stringify(attrs)).not.toContain("planted-delegated-token");
  });
});

describe("a recorded egress span", () => {
  it("carries only allowlisted keys", async () => {
    // Asserted on the RECORDED span rather than on the function, because a call
    // site can always set an attribute directly and bypass the builder.
    const span = tracer.startSpan("helix.egress.proxy");
    span.setAttributes(
      egressSpanAttributes({
        "helix.app_id": "app-1",
        "helix.outcome": "ok",
        "helix.upstream.status": 200,
      }),
    );
    span.end();

    const recorded = recording.spans()[0];
    expect(recorded).toBeDefined();
    for (const key of Object.keys(recorded?.attributes ?? {})) {
      expect(EGRESS_SPAN_ATTRS, `${key} is not on the egress allowlist`).toContain(key);
    }
  });

  it("carries the delegated resolution's span word vocabulary", async () => {
    // The resolution span is a new span name on this plane; its outcome words
    // are the span inventory, and every one must ride allowlisted KEYS
    // only. Asserted on a recorded span per outcome word, so a future word
    // that arrives carrying a non-allowlisted key fails here.
    for (const outcome of [
      "resolved",
      "refreshed",
      "connection_required",
      "reconnect_required",
      "provider_unavailable",
      "provider_misconfigured",
      "error",
    ]) {
      const span = tracer.startSpan("helix.egress.resolution");
      span.setAttributes(
        egressSpanAttributes({
          "helix.outcome": outcome,
          "helix.env": "prod",
          "helix.provider_ref": "asana",
        }),
      );
      span.end();
      const recorded = recording.spans().at(-1);
      expect(recorded?.attributes["helix.outcome"]).toBe(outcome);
      for (const key of Object.keys(recorded?.attributes ?? {})) {
        expect(EGRESS_SPAN_ATTRS, `${key} is not on the egress allowlist`).toContain(key);
      }
      expect(recorded?.events.filter((e) => e.name === "exception")).toEqual([]);
    }
  });

  it("stays on the allowlist when the edge hangs up before upstream headers", async () => {
    let headerTimer: ReturnType<typeof setTimeout> | undefined;
    const upstream = createServer((req, res) => {
      if (req.url !== "/slow-headers") {
        res.end("ok");
        return;
      }
      res.on("error", () => {});
      const stop = () => {
        if (headerTimer !== undefined) clearTimeout(headerTimer);
      };
      res.on("close", stop);
      req.on("close", stop);
      headerTimer = setTimeout(() => {
        res.writeHead(200);
        res.end("late");
      }, 3000);
    });
    await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;

    const config = {
      limits: { maxBodyBytes: 1024 * 1024, timeoutMs: 5000, llmTimeoutMs: 30_000 },
      allowPrivate: true,
      extraBlockedCidrs: [] as EgressConfig["extraBlockedCidrs"],
      allowInsecureConnection: true,
    } as EgressConfig;
    const app = buildApp({ config, resolver: null, instructionKey, burnStore: null });
    await app.listen({ port: 0, host: "127.0.0.1" });
    const base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;

    const requestId = randomUUID();
    const token = await new SignJWT({
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
      .sign(instructionKey);

    const ac = new AbortController();
    const pending = undiciRequest(`${base}/proxy`, {
      method: "POST",
      signal: ac.signal,
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/slow-headers`,
        [METHOD_HEADER]: "GET",
      },
    });
    await new Promise((r) => setTimeout(r, 80));
    ac.abort();
    try {
      await pending;
    } catch {
      // hang-up
    }
    await vi.waitFor(
      () => {
        expect(
          recording
            .spans()
            .some(
              (s) =>
                s.name === SPAN_EGRESS_PROXY && s.attributes[ATTR_CLIENT_DISCONNECTED] === true,
            ),
        ).toBe(true);
      },
      { timeout: 2000, interval: 25 },
    );

    const recorded = recording
      .spans()
      .filter((s) => s.name === SPAN_EGRESS_PROXY)
      .find((s) => s.attributes[ATTR_CLIENT_DISCONNECTED] === true);
    expect(recorded).toBeDefined();
    expect(recorded?.attributes[ATTR_CLIENT_DISCONNECTED]).toBe(true);
    expect(recorded?.attributes["helix.outcome"]).toBeUndefined();
    expect(recorded?.attributes["helix.upstream.status"]).toBeUndefined();
    expect(recorded?.events.filter((e) => e.name === "exception")).toEqual([]);
    const serialized = JSON.stringify(recorded?.attributes ?? {});
    expect(serialized).not.toMatch(/authorization|x-api-key|Bearer/i);
    for (const key of Object.keys(recorded?.attributes ?? {})) {
      expect(EGRESS_SPAN_ATTRS, `${key} is not on the egress allowlist`).toContain(key);
    }

    app.server.closeAllConnections();
    await app.close();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  });

  it("records no exception, because an egress error message can carry a secret", async () => {
    // `apps/egress/src/app.ts` returns a fixed opaque body for exactly this
    // reason, and `proxy.ts`'s injection `catch` deliberately binds nothing.
    // A span is a retained backend; the same rule applies.
    const span = tracer.startSpan("helix.egress.proxy");
    span.setStatus({ code: 2 });
    span.end();

    const recorded = recording.spans()[0];
    expect(recorded?.events.filter((e) => e.name === "exception")).toHaveLength(0);
    expect(recorded?.status.code).toBe(2);
  });
});
