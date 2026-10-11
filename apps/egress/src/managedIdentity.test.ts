import { randomBytes, randomUUID } from "node:crypto";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import {
  INSTRUCTION_AUDIENCE,
  INSTRUCTION_HEADER,
  INSTRUCTION_JWT_TYP,
  METHOD_HEADER,
  TARGET_HEADER,
} from "@azx-pbc/shared";
import type { TokenProvider } from "@azx-pbc/secret-store";
import { buildApp } from "./app.js";
import type { EgressConfig } from "./config.js";
import { deriveInstructionKey } from "./instruction.js";
import { ManagedIdentityResolver } from "./managedIdentity.js";
import type { ResolvedConnection, SecretResolver } from "./secrets.js";

/**
 * ADR-0046 — the keyless LLM credential path. The unit half pins the refusal
 * rules (capability, allowlist, host pin); the app-level half drives the full
 * /proxy chain through a stub token provider and an echo upstream, so the
 * injection itself — not just the resolver's return value — is asserted.
 */

const RULES = [{ connection: "foundry", hostSuffix: "services.ai.azure.com" }];
const FOUNDRY_ORIGIN = "https://contoso.services.ai.azure.com";

function stubTokenProvider(token = "mi-token"): TokenProvider & {
  getToken: ReturnType<typeof vi.fn>;
} {
  return { getToken: vi.fn(async () => token), close: vi.fn(async () => {}) };
}

/** A minimal inner resolver: one platform row named `seeded`, nothing else. */
function stubInner(): SecretResolver & {
  resolve: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
} {
  return {
    resolve: vi.fn(
      async (...args: Parameters<SecretResolver["resolve"]>): Promise<ResolvedConnection | null> =>
        args[1] === "seeded"
          ? { value: "stored-api-key", injection: { kind: "header-bearer" }, source: "secret" }
          : null,
    ),
    close: vi.fn(async () => {}),
  };
}

describe("ManagedIdentityResolver", () => {
  it("mints a bearer token for an allowlisted llm connection with a matching origin", async () => {
    const tokens = stubTokenProvider();
    const resolver = new ManagedIdentityResolver(stubInner(), tokens, RULES);
    const resolved = await resolver.resolve("app-1", "foundry", "llm", "prod", FOUNDRY_ORIGIN);
    expect(resolved).toEqual({
      value: "mi-token",
      injection: { kind: "header-bearer" },
      source: "managed-identity",
    });
    expect(tokens.getToken).toHaveBeenCalledOnce();
  });

  it("prefers a stored row over minting — explicit config beats ambient identity", async () => {
    const tokens = stubTokenProvider();
    const inner = stubInner();
    const resolver = new ManagedIdentityResolver(inner, tokens, RULES);
    const resolved = await resolver.resolve("app-1", "seeded", "llm", "prod", FOUNDRY_ORIGIN);
    expect(resolved?.value).toBe("stored-api-key");
    expect(resolved?.source).toBe("secret");
    expect(tokens.getToken).not.toHaveBeenCalled();
  });

  it("never mints for the fetch capability, even on an allowlisted name", async () => {
    const tokens = stubTokenProvider();
    const resolver = new ManagedIdentityResolver(stubInner(), tokens, RULES);
    await expect(
      resolver.resolve("app-1", "foundry", "fetch", "prod", FOUNDRY_ORIGIN),
    ).resolves.toBeNull();
    expect(tokens.getToken).not.toHaveBeenCalled();
  });

  it("never mints for a connection off the allowlist", async () => {
    const tokens = stubTokenProvider();
    const resolver = new ManagedIdentityResolver(stubInner(), tokens, RULES);
    await expect(
      resolver.resolve("app-1", "anthropic", "llm", "prod", FOUNDRY_ORIGIN),
    ).resolves.toBeNull();
    expect(tokens.getToken).not.toHaveBeenCalled();
  });

  // The host pin is the exfiltration guard: a forged instruction naming the
  // connection but a foreign origin must get nothing.
  it.each([
    "https://attacker.example",
    "https://evilservices.ai.azure.com", // suffix-lookalike, no dot boundary
    "https://services.ai.azure.com.evil.example", // suffix-in-name trap
    "not a url",
  ])("refuses to mint onto foreign origin %s", async (origin) => {
    const tokens = stubTokenProvider();
    const resolver = new ManagedIdentityResolver(stubInner(), tokens, RULES);
    await expect(resolver.resolve("app-1", "foundry", "llm", "prod", origin)).resolves.toBeNull();
    expect(tokens.getToken).not.toHaveBeenCalled();
  });

  it.each([FOUNDRY_ORIGIN, "https://a.b.services.ai.azure.com"])(
    "accepts the pinned host or its subdomains (%s)",
    async (origin) => {
      const resolver = new ManagedIdentityResolver(stubInner(), stubTokenProvider(), RULES);
      await expect(
        resolver.resolve("app-1", "foundry", "llm", "prod", origin),
      ).resolves.toMatchObject({ source: "managed-identity" });
    },
  );

  it("propagates a token-endpoint failure (the proxy maps it to an opaque 502)", async () => {
    const tokens = stubTokenProvider();
    tokens.getToken.mockRejectedValue(new Error("managed-identity token endpoint returned 400"));
    const resolver = new ManagedIdentityResolver(stubInner(), tokens, RULES);
    await expect(
      resolver.resolve("app-1", "foundry", "llm", "prod", FOUNDRY_ORIGIN),
    ).rejects.toThrow(/token endpoint/);
  });

  it("closing the wrapper closes the wrapped resolver", async () => {
    const inner = stubInner();
    const resolver = new ManagedIdentityResolver(inner, stubTokenProvider(), RULES);
    await resolver.close();
    expect(inner.close).toHaveBeenCalledOnce();
  });
});

// ── Full path: app + instruction + echo upstream ─────────────────────────────

const secret = randomBytes(32);
const key = deriveInstructionKey(secret);

let upstream: Server;
let origin: string;
beforeAll(async () => {
  upstream = createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ authorization: req.headers["authorization"] ?? null }));
  });
  await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

async function mint(claims: {
  origin: string;
  connection: string;
  capability: "fetch" | "llm";
}): Promise<string> {
  const requestId = randomUUID();
  const jwt = new SignJWT({
    appId: "app-1",
    userOid: "user-1",
    capability: claims.capability,
    origin: claims.origin,
    connection: claims.connection,
    env: "prod",
    requestId,
  })
    .setProtectedHeader({ alg: "HS256", typ: INSTRUCTION_JWT_TYP })
    .setJti(requestId)
    .setAudience(INSTRUCTION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("30s");
  return jwt.sign(key);
}

function makeApp(resolver: SecretResolver) {
  const config = {
    limits: { maxBodyBytes: 1024 * 1024, timeoutMs: 5000, llmTimeoutMs: 30_000 },
    allowPrivate: true, // loopback echo upstream
    extraBlockedCidrs: [] as EgressConfig["extraBlockedCidrs"],
    allowInsecureConnection: true, // loopback is http; the prod guard is pinned in adversarial.test.ts
  } as EgressConfig;
  return buildApp({ config, resolver, instructionKey: key, burnStore: null });
}

describe("ManagedIdentityResolver over /proxy", () => {
  // The host suffix here is the loopback echo's, because the point is the
  // injection chain, not the suffix grammar (pinned by the unit half).
  const loopbackRules = [{ connection: "foundry", hostSuffix: "127.0.0.1" }];

  it("injects a minted bearer token the app never possessed", async () => {
    const resolver = new ManagedIdentityResolver(stubInner(), stubTokenProvider("live-mi-token"), [
      { connection: "foundry", hostSuffix: "127.0.0.1" },
    ]);
    const app = makeApp(resolver);
    const token = await mint({ origin, connection: "foundry", capability: "llm" });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/v1/messages`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().authorization).toBe("Bearer live-mi-token");
    await app.close();
  });

  it("a fetch instruction naming the same connection gets nothing", async () => {
    const tokens = stubTokenProvider();
    const resolver = new ManagedIdentityResolver(stubInner(), tokens, loopbackRules);
    const app = makeApp(resolver);
    const token = await mint({ origin, connection: "foundry", capability: "fetch" });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(403);
    expect(tokens.getToken).not.toHaveBeenCalled();
    await app.close();
  });

  // Telemetry ships with the seam: which credential source served a call is
  // the first thing an operator needs when a Foundry-bound call 401s.
  describe("telemetry", () => {
    let recording: RecordingTelemetry;
    beforeAll(() => {
      recording = startRecordingTelemetry();
    });
    afterEach(() => recording.reset());
    afterAll(async () => {
      await recording.restore();
    });

    it("records helix.credential_source=managed-identity on the proxy span", async () => {
      const resolver = new ManagedIdentityResolver(stubInner(), stubTokenProvider(), loopbackRules);
      const app = makeApp(resolver);
      const token = await mint({ origin, connection: "foundry", capability: "llm" });
      const res = await app.inject({
        method: "POST",
        url: "/proxy",
        headers: {
          [INSTRUCTION_HEADER]: token,
          [TARGET_HEADER]: `${origin}/v1/messages`,
          [METHOD_HEADER]: "GET",
        },
      });
      expect(res.statusCode).toBe(200);
      await app.close();

      const span = recording.spans().find((s) => s.name === "helix.egress.proxy");
      expect(span?.attributes["helix.credential_source"]).toBe("managed-identity");
      expect(span?.attributes["helix.connection"]).toBe("foundry");
    });
  });
});
