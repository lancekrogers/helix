import { randomBytes, randomUUID } from "node:crypto";
import { type IncomingMessage, type ServerResponse, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Writable } from "node:stream";
import { SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import {
  ConnectionProviderSchema,
  type ConnectionProvider,
  EXCHANGE_AUDIENCE,
  EXCHANGE_AUTH_HEADER,
  EXCHANGE_JWT_TYP,
  ExchangeResponseSchema,
} from "@azx-pbc/shared";
import { SPAN_EGRESS_EXCHANGE } from "@azx-pbc/shared/telemetry";
import {
  startDevOAuthVendor,
  requestAuthorizationCode,
  newCodeVerifier,
  s256CodeChallenge,
  type RunningDevOAuthVendor,
} from "@azx-pbc/dev-oauth-vendor";
import { createSecretStore, type SecretStore } from "@azx-pbc/secret-store";
import { buildApp } from "./app.js";
import type { EgressConfig } from "./config.js";
import { makePinnedFetch } from "./exchangeTransport.js";
import { deriveExchangeKey } from "./internalJwt.js";
import type { ProviderCacheReader } from "./providerCache.js";
import { deriveInstructionKey } from "./instruction.js";
import { makePinnedDispatcher, SsrfBlockedError } from "./ssrf.js";
import { EGRESS_SPAN_ATTRS } from "./spanAttributes.js";

/**
 * The code-exchange operation against the REAL
 * fixture vendor through the real route: authz, the compatibility
 * gate at receipt, sealing, the fixed-string failure discipline, and the
 * pinned-transport proof.
 */

const exchangeKey = deriveExchangeKey(randomBytes(32));
const instructionKey = deriveInstructionKey(randomBytes(32));
const DEV_KEK = randomBytes(32);

/** The edge-supplied fixed callback — the consult's redirect_uri. */
const REDIRECT_URI = "https://auth.local.helix.azxlabs.io/connections/callback";

/** Distinctive needles for the leak scans — never real credentials. */
const VENDOR_BODY_SENTINEL = "SENTINEL_VENDOR_BODY_9f8e7d6c";
const CLIENT_ID = "dev-oauth-client";
const CLIENT_SECRET = "dev-oauth-secret-4f2a";

let vendor: RunningDevOAuthVendor;
let recording: RecordingTelemetry;

beforeAll(async () => {
  recording = startRecordingTelemetry();
  vendor = await startDevOAuthVendor({
    accessTokenTtlSeconds: 900,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  });
});

afterEach(() => {
  recording.reset();
  delegated.resetSeals();
  vendor.setModes({ tokenMode: "rotating", authorizeMode: "approve" });
});

afterAll(async () => {
  await recording.restore();
  await vendor.close();
});

/** The delegated store, instrumented so "nothing sealed" is observable. */
class RecordingDelegatedStore implements SecretStore {
  readonly seals: string[] = [];
  readonly inner: SecretStore = createSecretStore({ devMasterKey: DEV_KEK });
  seal(value: string): Promise<string> {
    this.seals.push(value);
    return this.inner.seal(value);
  }
  open(material: string): Promise<string> {
    return this.inner.open(material);
  }
  destroy(material: string): Promise<void> {
    return this.inner.destroy(material);
  }
  resetSeals(): void {
    this.seals.length = 0;
  }
}

const delegated = new RecordingDelegatedStore();
const credentialStore = createSecretStore({ devMasterKey: DEV_KEK });

/**
 * A provider row pointing at the fixture vendor, with the client credentials
 * sealed through the same custody the egress process opens them with. Cases
 * rebuild it (scopes/revision/env/endpoint vary) BEFORE making the app.
 */
let provider: ConnectionProvider;
async function setProvider(overrides: Partial<ConnectionProvider> = {}): Promise<void> {
  provider = ConnectionProviderSchema.parse({
    id: randomUUID(),
    ref: "fixture-vendor",
    kind: "rest-delegated",
    displayName: "Fixture Vendor",
    authorizeEndpoint: `${vendor.issuer}/authorize`,
    tokenEndpoint: `${vendor.issuer}/token`,
    requestedScopes: [],
    apiOrigins: ["https://api.fixture.test"],
    tokenPlacement: { kind: "header-bearer" },
    env: "prod",
    clientIdMaterial: await credentialStore.seal(CLIENT_ID),
    clientSecretMaterial: await credentialStore.seal(CLIENT_SECRET),
    revision: 1,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  });
}

function cacheOf(row: ConnectionProvider | undefined): ProviderCacheReader {
  return {
    get: (id) => (row !== undefined && id === row.id ? row : undefined),
    getByRef: () => row,
    isLoaded: () => true,
  };
}

interface AppOpts {
  allowPrivate?: boolean;
  allowInsecureConnection?: boolean;
  timeoutMs?: number;
  providers?: ProviderCacheReader;
  delegatedStore?: SecretStore;
  /** Replaces the pino instance with a capture-stream logger (the log scans). */
  logCapture?: Writable;
}

function makeApp(opts: AppOpts = {}) {
  const config = {
    limits: { maxBodyBytes: 1024 * 1024, timeoutMs: opts.timeoutMs ?? 5_000 },
    allowPrivate: opts.allowPrivate ?? true,
    extraBlockedCidrs: [] as EgressConfig["extraBlockedCidrs"],
    allowInsecureConnection: opts.allowInsecureConnection ?? true,
  } as EgressConfig;
  return buildApp(
    {
      config,
      resolver: null,
      instructionKey,
      burnStore: null,
      exchange: {
        exchangeKey,
        providers: opts.providers ?? cacheOf(provider),
        credentialStore,
        delegatedStore: opts.delegatedStore ?? delegated,
        allowPrivate: opts.allowPrivate ?? true,
        allowInsecureConnection: opts.allowInsecureConnection ?? true,
        timeoutMs: opts.timeoutMs ?? 5_000,
      },
    },
    opts.logCapture ? { level: "info", stream: opts.logCapture } : undefined,
  );
}

/** Mint the portal→egress exchange token the way the portal side writes it. */
async function mint(signKey: Buffer = exchangeKey, audience = EXCHANGE_AUDIENCE): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "HS256", typ: EXCHANGE_JWT_TYP })
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("30s")
    .sign(signKey);
}

/** Drive the fixture's authorize endpoint for a real grant code bound to `verifier`. */
async function driveCode(opts: { verifier: string; scope?: string }): Promise<string> {
  const auth = await requestAuthorizationCode(vendor, {
    redirectUri: REDIRECT_URI,
    challenge: s256CodeChallenge(opts.verifier),
    scope: opts.scope,
  });
  expect(auth.code).toBeTruthy();
  return auth.code as string;
}

/**
 * POST the exchange body. `token` semantics: omit the argument to mint a fresh
 * valid token; pass `null` to send NO authorization header at all.
 */
async function postExchange(
  app: ReturnType<typeof buildApp>,
  body: unknown,
  token?: string | null,
) {
  return app.inject({
    method: "POST",
    url: "/exchange",
    headers: {
      "content-type": "application/json",
      ...(token === null ? {} : { [EXCHANGE_AUTH_HEADER]: token ?? (await mint()) }),
    },
    payload: JSON.stringify(body),
  });
}

function exchangeBody(code: string, verifier: string, overrides: Record<string, unknown> = {}) {
  return {
    providerId: provider.id,
    providerRevision: provider.revision,
    env: provider.env,
    code,
    codeVerifier: verifier,
    redirectUri: REDIRECT_URI,
    ...overrides,
  };
}

/** A raw token endpoint with a scripted response and a request counter. */
interface ScriptedTokenServer {
  origin: string;
  received: () => number;
  close: () => Promise<void>;
}

type Script = (req: IncomingMessage, res: ServerResponse) => void;

function scriptedTokenServer(script: Script): Promise<ScriptedTokenServer> {
  let count = 0;
  const server = createServer((req, res) => {
    count += 1;
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => script(req, res));
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        origin: `http://127.0.0.1:${port}`,
        received: () => count,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

const jsonResponse =
  (body: Record<string, unknown>, status = 200): Script =>
  (_req, res) => {
    res.statusCode = status;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(body));
  };

describe("POST /exchange — the happy path", () => {
  it("exchanges a valid fixture grant code + verifier and seals both materials", async () => {
    await setProvider({ requestedScopes: ["email", "profile"] });
    const app = makeApp();
    const verifier = newCodeVerifier();
    const code = await driveCode({ verifier, scope: "email profile" });

    const res = await postExchange(app, exchangeBody(code, verifier));
    expect(res.statusCode).toBe(200);

    // The response parses through THE schema, as the `exchanged` variant —
    // which is exactly the metadata + sealed references shape (strictObject
    // refuses anything else on the wire).
    const body = ExchangeResponseSchema.parse(res.json());
    expect(body.outcome).toBe("exchanged");
    if (body.outcome !== "exchanged") return; // narrowing
    expect(body.grantedScopes).toEqual(["email", "profile"]);

    // Sealed references open (dev envelope) to fixture-shaped tokens, and the
    // PLAINTEXTS appear nowhere in the response — the property that makes it
    // safe for the portal to hold the body at all.
    const openedAccess = await delegated.open(body.access);
    const openedRefresh = await delegated.open(body.refresh);
    expect(openedAccess).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(openedRefresh).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(res.body).not.toContain(openedAccess);
    expect(res.body).not.toContain(openedRefresh);

    // Metadata: the access expiry honors the vendor's `expires_in` (900s).
    const expiry = Date.parse(body.accessExpiresAt);
    expect(expiry).toBeGreaterThan(Date.now() + 800_000);
    expect(expiry).toBeLessThan(Date.now() + 1_000_000);

    await app.close();
  });

  it("accepts an omitted granted-permissions field as granted", async () => {
    await setProvider({ requestedScopes: ["email", "profile"] });
    const app = makeApp();
    const verifier = newCodeVerifier();
    // No scope on the authorize request ⇒ the fixture's token response omits
    // `scope` entirely (grant.scope === "") — the omitted-means-granted shape.
    const code = await driveCode({ verifier });

    const res = await postExchange(app, exchangeBody(code, verifier));
    const body = ExchangeResponseSchema.parse(res.json());
    expect(body.outcome).toBe("exchanged");
    if (body.outcome !== "exchanged") return;
    expect(body.grantedScopes).toEqual(["email", "profile"]);
    await app.close();
  });

  it("accepts a strict superset of the configured permissions", async () => {
    await setProvider({ requestedScopes: ["email"] });
    const app = makeApp();
    const verifier = newCodeVerifier();
    const code = await driveCode({ verifier, scope: "email profile" });

    const res = await postExchange(app, exchangeBody(code, verifier));
    const body = ExchangeResponseSchema.parse(res.json());
    expect(body.outcome).toBe("exchanged");
    if (body.outcome !== "exchanged") return;
    expect(body.grantedScopes).toEqual(["email", "profile"]);
    await app.close();
  });
});

describe("POST /exchange — the compatibility gate at receipt", () => {
  it("rejects an explicitly smaller permission set with nothing sealed", async () => {
    await setProvider({ requestedScopes: ["email", "profile"] });
    const app = makeApp();
    const verifier = newCodeVerifier();
    const code = await driveCode({ verifier, scope: "email" }); // profile missing

    const res = await postExchange(app, exchangeBody(code, verifier));
    expect(res.statusCode).toBe(200);
    expect(ExchangeResponseSchema.parse(res.json())).toEqual({
      outcome: "rejected",
      reason: "missing_permissions",
    });
    expect(delegated.seals).toHaveLength(0);
    await app.close();
  });

  it("rejects a response with no refresh token with nothing sealed", async () => {
    const tokenServer = await scriptedTokenServer(
      jsonResponse({
        access_token: "a".repeat(43),
        token_type: "Bearer",
        expires_in: 900,
        scope: "email",
      }),
    );
    try {
      await setProvider({ tokenEndpoint: `${tokenServer.origin}/token` });
      const app = makeApp();
      const res = await postExchange(app, exchangeBody("any-code", newCodeVerifier()));
      expect(ExchangeResponseSchema.parse(res.json())).toEqual({
        outcome: "rejected",
        reason: "missing_refresh_token",
      });
      expect(tokenServer.received()).toBe(1); // the vendor WAS called
      expect(delegated.seals).toHaveLength(0); // …and nothing was sealed
      await app.close();
    } finally {
      await tokenServer.close();
    }
  });

  it("rejects an absent lifetime with nothing sealed", async () => {
    const tokenServer = await scriptedTokenServer(
      jsonResponse({
        access_token: "a".repeat(43),
        token_type: "Bearer",
        refresh_token: "r".repeat(43),
      }),
    );
    try {
      await setProvider({ tokenEndpoint: `${tokenServer.origin}/token` });
      const app = makeApp();
      const res = await postExchange(app, exchangeBody("any-code", newCodeVerifier()));
      expect(ExchangeResponseSchema.parse(res.json())).toEqual({
        outcome: "rejected",
        reason: "unusable_lifetime",
      });
      expect(delegated.seals).toHaveLength(0);
      await app.close();
    } finally {
      await tokenServer.close();
    }
  });

  it("rejects a non-positive lifetime with nothing sealed", async () => {
    const tokenServer = await scriptedTokenServer(
      jsonResponse({
        access_token: "a".repeat(43),
        token_type: "Bearer",
        refresh_token: "r".repeat(43),
        expires_in: 0,
      }),
    );
    try {
      await setProvider({ tokenEndpoint: `${tokenServer.origin}/token` });
      const app = makeApp();
      const res = await postExchange(app, exchangeBody("any-code", newCodeVerifier()));
      expect(ExchangeResponseSchema.parse(res.json())).toEqual({
        outcome: "rejected",
        reason: "unusable_lifetime",
      });
      expect(delegated.seals).toHaveLength(0);
      await app.close();
    } finally {
      await tokenServer.close();
    }
  });
});

describe("POST /exchange — provider resolution", () => {
  it("answers provider_unavailable for an unknown provider id", async () => {
    await setProvider();
    const app = makeApp();
    const res = await postExchange(
      app,
      exchangeBody("any-code", newCodeVerifier(), { providerId: randomUUID() }),
    );
    expect(ExchangeResponseSchema.parse(res.json())).toEqual({ outcome: "provider_unavailable" });
    await app.close();
  });

  it("answers provider_unavailable for a stale revision stamp", async () => {
    await setProvider({ revision: 7 });
    const app = makeApp();
    const res = await postExchange(
      app,
      exchangeBody("any-code", newCodeVerifier(), { providerRevision: 6 }),
    );
    expect(ExchangeResponseSchema.parse(res.json())).toEqual({ outcome: "provider_unavailable" });
    await app.close();
  });

  it("answers provider_unavailable for a wrong env", async () => {
    await setProvider({ env: "dev" });
    const app = makeApp();
    const res = await postExchange(
      app,
      exchangeBody("any-code", newCodeVerifier(), { env: "prod" }),
    );
    expect(ExchangeResponseSchema.parse(res.json())).toEqual({ outcome: "provider_unavailable" });
    await app.close();
  });
});

describe("POST /exchange — authorization before anything else", () => {
  it("refuses a missing token before the body is parsed and the vendor is called", async () => {
    const tokenServer = await scriptedTokenServer(jsonResponse({}));
    try {
      await setProvider({ tokenEndpoint: `${tokenServer.origin}/token` });
      const app = makeApp();
      const res = await postExchange(
        app,
        exchangeBody("any-code", newCodeVerifier()),
        null, // no header at all
      );
      expect(res.statusCode).toBe(401);
      expect(tokenServer.received()).toBe(0);
      await app.close();
    } finally {
      await tokenServer.close();
    }
  });

  it("refuses a wrong-audience token before the vendor is called", async () => {
    const tokenServer = await scriptedTokenServer(jsonResponse({}));
    try {
      await setProvider({ tokenEndpoint: `${tokenServer.origin}/token` });
      const app = makeApp();
      const res = await postExchange(
        app,
        exchangeBody("any-code", newCodeVerifier()),
        await mint(exchangeKey, "azx-somewhere-else"),
      );
      expect(res.statusCode).toBe(401);
      expect(tokenServer.received()).toBe(0);
      await app.close();
    } finally {
      await tokenServer.close();
    }
  });

  it("refuses an expired token before the vendor is called", async () => {
    const tokenServer = await scriptedTokenServer(jsonResponse({}));
    try {
      await setProvider({ tokenEndpoint: `${tokenServer.origin}/token` });
      const app = makeApp();
      const now = Math.floor(Date.now() / 1000);
      const expired = await new SignJWT({})
        .setProtectedHeader({ alg: "HS256", typ: EXCHANGE_JWT_TYP })
        .setAudience(EXCHANGE_AUDIENCE)
        .setIssuedAt(now - 120)
        .setExpirationTime(now - 60)
        .sign(exchangeKey);
      const res = await postExchange(app, exchangeBody("any-code", newCodeVerifier()), expired);
      expect(res.statusCode).toBe(401);
      expect(tokenServer.received()).toBe(0);
      await app.close();
    } finally {
      await tokenServer.close();
    }
  });

  it("refuses garbage in the authorization header", async () => {
    await setProvider();
    const app = makeApp();
    const res = await postExchange(app, exchangeBody("any-code", newCodeVerifier()), "garbage");
    expect(res.statusCode).toBe(401);
    await app.close();
  });

  it("answers a malformed body 400 after authorization", async () => {
    await setProvider();
    const app = makeApp();
    const res = await app.inject({
      method: "POST",
      url: "/exchange",
      headers: { "content-type": "application/json", [EXCHANGE_AUTH_HEADER]: await mint() },
      payload: "not json {",
    });
    expect(res.statusCode).toBe(400);
    await app.close();
  });

  it("refuses a verified caller with 503 when no custody is configured", async () => {
    await setProvider();
    // A wired exchange op with null stores — keyless egress receiving a call.
    const config = {
      limits: { maxBodyBytes: 1024 * 1024, timeoutMs: 5_000 },
      allowPrivate: true,
      extraBlockedCidrs: [] as EgressConfig["extraBlockedCidrs"],
      allowInsecureConnection: true,
    } as EgressConfig;
    const app = buildApp({
      config,
      resolver: null,
      instructionKey,
      burnStore: null,
      exchange: {
        exchangeKey,
        providers: cacheOf(provider),
        credentialStore: null,
        delegatedStore: null,
        allowPrivate: true,
        allowInsecureConnection: true,
        timeoutMs: 5_000,
      },
    });
    const res = await postExchange(app, exchangeBody("any-code", newCodeVerifier()));
    expect(res.statusCode).toBe(503);
    await app.close();
  });
});

describe("POST /exchange — fixed-string failures", () => {
  /**
   * Drive a vendor failure, then scan every retained backend the path touches:
   * the response body (the fixed union, nothing else), the span (no exception
   * event, only allowlisted attributes, no vendor content), and the LOG (pino's
   * err serializer writes whatever it is handed verbatim — the handler's
   * discipline is that it is handed nothing vendor-shaped or credential-shaped).
   */
  async function scanVendorFailure(opts: {
    vendorMode?: "hang" | "consumed-then-drop";
    script?: Script;
  }): Promise<void> {
    const chunks: string[] = [];
    const capture = new Writable({
      write(chunk: unknown, _enc: BufferEncoding, cb: (e?: Error | null) => void) {
        chunks.push(String(chunk));
        cb();
      },
    });

    let tokenServer: ScriptedTokenServer | null = null;
    if (opts.script) {
      tokenServer = await scriptedTokenServer(opts.script);
      await setProvider({ tokenEndpoint: `${tokenServer.origin}/token` });
    } else {
      await setProvider();
      if (opts.vendorMode) vendor.setModes({ tokenMode: opts.vendorMode });
    }

    const app = makeApp({
      timeoutMs: opts.vendorMode === "hang" ? 300 : 5_000,
      logCapture: capture,
    });

    try {
      const verifier = newCodeVerifier();
      const code = await driveCode({ verifier, scope: "email" }).catch(() => "unused-code");
      const res = await postExchange(app, exchangeBody(code, verifier));

      // The fixed-string outcome: the body parses to the ONE opaque variant
      // and carries nothing else.
      expect(res.statusCode).toBe(200);
      expect(ExchangeResponseSchema.parse(res.json())).toEqual({ outcome: "exchange_failed" });
      expect(res.body).not.toContain(VENDOR_BODY_SENTINEL);
      expect(res.body).not.toContain(CLIENT_SECRET);

      // Nothing was sealed on a vendor failure.
      expect(delegated.seals).toHaveLength(0);

      // The span: outcome word only — no exception event, no vendor content.
      const spans = recording.spans().filter((s) => s.name === SPAN_EGRESS_EXCHANGE);
      expect(spans.length).toBeGreaterThan(0);
      for (const span of spans) {
        expect(span.events.filter((e) => e.name === "exception")).toHaveLength(0);
        for (const key of Object.keys(span.attributes)) {
          expect(EGRESS_SPAN_ATTRS, `${key} is not on the egress allowlist`).toContain(key);
        }
        expect(JSON.stringify(span.attributes)).not.toContain(VENDOR_BODY_SENTINEL);
        expect(JSON.stringify(span.attributes)).not.toContain(CLIENT_SECRET);
      }

      // The log: no vendor response content, no credential material.
      await app.close();
      const logged = chunks.join("");
      expect(logged).not.toContain(VENDOR_BODY_SENTINEL);
      expect(logged).not.toContain(CLIENT_SECRET);
      expect(logged).toContain("exchange.failed");
    } finally {
      await app.close().catch(() => {});
      if (tokenServer) await tokenServer.close();
    }
  }

  it("a hanging token endpoint surfaces as the opaque outcome", async () => {
    await scanVendorFailure({ vendorMode: "hang" });
  });

  it("a 5xx token endpoint surfaces as the opaque outcome, vendor body unread", async () => {
    await scanVendorFailure({
      script: (_req, res) => {
        res.statusCode = 500;
        res.setHeader("content-type", "text/html");
        res.end(`<html>${VENDOR_BODY_SENTINEL}</html>`);
      },
    });
  });

  it("a malformed token response surfaces as the opaque outcome", async () => {
    await scanVendorFailure({
      script: (_req, res) => {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(`{"access_token": ${VENDOR_BODY_SENTINEL}`); // broken JSON
      },
    });
  });

  it("a standard OAuth error (consumed grant) surfaces as the opaque outcome", async () => {
    await scanVendorFailure({ vendorMode: "consumed-then-drop" });
  });
});

describe("POST /exchange — the pinned transport", () => {
  it("refuses a loopback token endpoint in the prod-flag posture before dialing", async () => {
    const tokenServer = await scriptedTokenServer(
      jsonResponse({
        access_token: "a".repeat(43),
        token_type: "Bearer",
        refresh_token: "r".repeat(43),
        expires_in: 900,
      }),
    );
    try {
      await setProvider({ tokenEndpoint: `${tokenServer.origin}/token` });
      // Prod posture: no dev seams at all.
      const app = makeApp({ allowPrivate: false, allowInsecureConnection: false });
      const res = await postExchange(app, exchangeBody("any-code", newCodeVerifier()));
      expect(ExchangeResponseSchema.parse(res.json())).toEqual({ outcome: "exchange_failed" });
      expect(tokenServer.received()).toBe(0);
      await app.close();
    } finally {
      await tokenServer.close();
    }
  });

  it("the SSRF suites' class, extended to the adapter: blocked under prod flags", async () => {
    const prodFetch = makePinnedFetch(makePinnedDispatcher(false, 1_000, []));
    // undici's fetch wraps the connector's refusal as the `cause` of a
    // "fetch failed" TypeError — the same SsrfBlockedError the proxy's
    // `request()` path propagates verbatim.
    const refused = async (p: Promise<unknown>): Promise<void> => {
      try {
        await p;
        throw new Error("expected an SSRF refusal");
      } catch (err) {
        expect((err as { cause?: unknown }).cause).toBeInstanceOf(SsrfBlockedError);
      }
    };
    // Loopback https (undici treats port 9 as a browser bad-port and refuses
    // before any connector runs, so use a real high port) and the IMDS address.
    await refused(
      prodFetch("https://127.0.0.1:59999/token", {
        method: "POST",
        headers: {},
        body: "",
        redirect: "manual",
      }),
    );
    await refused(
      prodFetch("http://169.254.169.254/latest/meta-data", {
        method: "GET",
        headers: {},
        body: undefined,
        redirect: "manual",
      }),
    );
    // An RFC 1918 target too — the class, not one address.
    await refused(
      prodFetch("https://10.0.0.1:3443/token", {
        method: "POST",
        headers: {},
        body: "",
        redirect: "manual",
      }),
    );
  });

  it("the SSRF suites' class, extended to the adapter: the dev seams open the same dial", async () => {
    const devFetch = makePinnedFetch(makePinnedDispatcher(true, 1_000, []));
    // The same loopback target: the connection is now ATTEMPTED (nothing
    // listens on :59999, so the dial fails with a connect error, not an SSRF
    // refusal) — the control, not the address, is what flipped.
    let refused: unknown;
    try {
      await devFetch("https://127.0.0.1:59999/token", {
        method: "POST",
        headers: {},
        body: "",
        redirect: "manual",
      });
      throw new Error("the private dial should have failed to connect");
    } catch (err) {
      refused = err;
    }
    expect((refused as { cause?: unknown }).cause).not.toBeInstanceOf(SsrfBlockedError);
  });

  it("the happy path reaches the loopback vendor through the validating connector", async () => {
    // The fixture vendor is loopback + http: the exchange reaching it at all
    // proves the library's calls flow through the validating connector under
    // the dev seams — the adapter is load-bearing, not decorative.
    await setProvider({ requestedScopes: ["email"] });
    const app = makeApp();
    const verifier = newCodeVerifier();
    const code = await driveCode({ verifier, scope: "email" });
    const res = await postExchange(app, exchangeBody(code, verifier));
    expect(ExchangeResponseSchema.parse(res.json()).outcome).toBe("exchanged");
    await app.close();
  });
});

describe("POST /exchange — telemetry (ADR-0037)", () => {
  it("the span carries only allowlisted, bounded, non-personal attributes", async () => {
    await setProvider({ requestedScopes: ["email"] });
    const app = makeApp();
    const verifier = newCodeVerifier();
    const code = await driveCode({ verifier, scope: "email" });
    await postExchange(app, exchangeBody(code, verifier));
    await app.close();

    const spans = recording.spans().filter((s) => s.name === SPAN_EGRESS_EXCHANGE);
    expect(spans).toHaveLength(1);
    const span = spans[0]!;
    for (const key of Object.keys(span.attributes)) {
      expect(EGRESS_SPAN_ATTRS).toContain(key);
    }
    expect(span.attributes["helix.outcome"]).toBe("exchanged");
    expect(span.attributes["helix.env"]).toBe("prod");
    expect(span.attributes["helix.provider_ref"]).toBe("fixture-vendor");
    // No identity dimension, no exception: the material the operation moves is
    // exactly the material a span must never carry.
    expect(JSON.stringify(span.attributes)).not.toMatch(/user|oid/i);
    expect(span.events.filter((e) => e.name === "exception")).toHaveLength(0);
  });

  it("the counter counts by outcome and env", async () => {
    await setProvider({ requestedScopes: ["email"] });
    const app = makeApp();
    const verifier = newCodeVerifier();
    const code = await driveCode({ verifier, scope: "email" });
    await postExchange(app, exchangeBody(code, verifier));
    await app.close();

    const metrics = await recording.metrics();
    const exchanges = metrics.filter((m) => m.name === "helix.egress.exchanges");
    expect(exchanges.length).toBeGreaterThan(0);
    const exchanged = exchanges.find(
      (m) => m.attributes["helix.outcome"] === "exchanged" && m.attributes["helix.env"] === "prod",
    );
    expect(exchanged?.value).toBeGreaterThanOrEqual(1);
    for (const point of exchanges) {
      for (const key of Object.keys(point.attributes)) {
        expect(["helix.outcome", "helix.env"]).toContain(key);
      }
    }
  });
});
