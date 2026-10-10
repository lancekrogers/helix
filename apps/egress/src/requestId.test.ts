import { describe, expect, it } from "vitest";
import { REQUEST_ID_HEADER } from "@azx-pbc/shared/logging";
import { buildApp } from "./app.js";
import type { EgressConfig } from "./config.js";

/**
 * Egress is the one service that adopts its caller's request id, because its
 * only caller is the edge over a hop whose authority comes from the signed
 * attested instruction (ADR-0013). Adopting it is what joins the two halves of
 * a fetch-proxy call — which today land in two different Log Analytics
 * workspaces with nothing in common but a timestamp.
 *
 * These drive `/health` rather than `/proxy`: `req.id` is assigned by Fastify
 * before any route runs, so the cheapest unauthenticated route exercises the
 * generator without standing up an instruction, a burn store and an upstream.
 */

function buildEgress() {
  const config = {
    limits: { maxBodyBytes: 1024 * 1024, timeoutMs: 5000, llmTimeoutMs: 30_000 },
    allowPrivate: false,
    allowInsecureConnection: false,
  } as EgressConfig;
  return buildApp({
    config,
    resolver: null,
    instructionKey: Buffer.alloc(32),
    burnStore: null,
  });
}

/** Fastify exposes the generated id on the reply's `request-id` — read it off the app instead. */
async function requestIdFor(headers: Record<string, string>): Promise<string> {
  const app = buildEgress();
  let seen = "";
  app.addHook("onRequest", async (req) => {
    seen = String(req.id);
  });
  const res = await app.inject({ method: "GET", url: "/health", headers });
  expect(res.statusCode).toBe(200);
  await app.close();
  return seen;
}

const VALID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

describe("egress request-id adoption", () => {
  it("adopts a valid inbound correlation id", async () => {
    expect(await requestIdFor({ [REQUEST_ID_HEADER]: VALID })).toBe(VALID);
  });

  it("mints its own when the caller sends none", async () => {
    const id = await requestIdFor({});
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it("refuses a malformed id rather than putting it on every log line", async () => {
    // Egress has `external: true` ingress. Its authority still comes from the
    // instruction — a forged header buys nothing — but an unvalidated value
    // would let a caller inject a newline (forging a second log entry) or 8KB
    // of padding into a field retained for 30 days.
    for (const forged of ["a\nb", `${VALID}\ninjected`, "x".repeat(8192), "not-a-uuid"]) {
      const id = await requestIdFor({ [REQUEST_ID_HEADER]: forged });
      expect(id).not.toBe(forged);
      expect(id).not.toContain("\n");
      expect(id.length).toBe(36);
    }
  });
});
