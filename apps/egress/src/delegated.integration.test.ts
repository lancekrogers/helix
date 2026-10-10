import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { SignJWT } from "jose";
import { Pool } from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import {
  type ConnectionProvider,
  ConnectionProviderSchema,
  ConnectionMaterialSchema,
  type Env,
  type PrincipalKind,
  type UserConnection,
  INSTRUCTION_AUDIENCE,
  INSTRUCTION_HEADER,
  INSTRUCTION_JWT_TYP,
  METHOD_HEADER,
  OUTCOME_HEADER,
  TARGET_HEADER,
} from "@azx-pbc/shared";
import {
  SPAN_EGRESS_PROXY,
  SPAN_EGRESS_RESOLUTION,
  SPAN_EGRESS_RENEWAL,
} from "@azx-pbc/shared/telemetry";
import {
  startDevOAuthVendor,
  requestAuthorizationCode,
  exchangeAuthorizationCode,
  newCodeVerifier,
  s256CodeChallenge,
  type RunningDevOAuthVendor,
} from "@azx-pbc/dev-oauth-vendor";
import { createSecretStore, type SecretStore } from "@azx-pbc/secret-store";
import { buildApp } from "./app.js";
import type { EgressConfig } from "./config.js";
import { deriveInstructionKey } from "./instruction.js";
import type { SecretResolver } from "./secrets.js";
import { userConnectionFromPg } from "./renewal.js";
import { createEgressPool } from "./pool.js";
import { EGRESS_SPAN_ATTRS } from "./spanAttributes.js";

/**
 * The delegated-call path end to end against the REAL test
 * database and the REAL fixture vendor: a `provider`-bearing attested
 * instruction — minted the
 * way the edge mints them (the shared sign helpers, with the caller kind the
 * strict schema requires) — resolves the caller's connection, injects the
 * access token in the provider's placement, renews when due, and refuses
 * every failure class the error table names BEFORE any vendor
 * traffic.
 *
 * Two vendor surfaces cooperate: the fixture's OAuth endpoints (the code
 * grant that seeds real connections, and the token-endpoint call log — the
 * single-flight/never-renewed evidence) and its API destination — the header
 * echo every placement assertion reads back through the proxied response. A
 * scripted origin stands in as the API destination where the test needs a
 * vendor 401 or a request log the fixture does not keep.
 *
 * Seeding runs as the table owner (the portal's job); the resolution runs
 * under `helix_egress`. Skips when the role isn't provisioned — the other
 * integration suites' fail-soft stance.
 */

const OWNER_URL = process.env.TEST_DATABASE_URL ?? "postgresql://helix:helix@db:5432/helix_test";

function egressUrl(): string {
  const u = new URL(OWNER_URL);
  u.username = "helix_egress";
  u.password = "helix_egress";
  return u.toString();
}

let ok = false;
beforeAll(async () => {
  const probe = new Pool({ connectionString: egressUrl(), max: 1 });
  try {
    await probe.query("SELECT 1");
    ok = true;
  } catch {
    ok = false;
  } finally {
    await probe.end();
  }
});

const recording: RecordingTelemetry = startRecordingTelemetry();

const VENDOR_TIMEOUT_MS = 2_000;
const REDIRECT_URI = "https://auth.local.helix.azxlabs.io/connections/callback";
const CLIENT_ID = "delegated-fixture-client";
const CLIENT_SECRET = "delegated-fixture-secret-77cd";
const NAMED_HEADER = "x-user-token";

let vendor: RunningDevOAuthVendor;
const kek = Buffer.from("delegated-test-kek-0123456789abcdef", "utf8");
const credentialStore: SecretStore = createSecretStore({ devMasterKey: kek });

beforeAll(async () => {
  vendor = await startDevOAuthVendor({
    accessTokenTtlSeconds: 900,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  });
});

const seededConnectionIds: string[] = [];
const seededProviderIds: string[] = [];

afterAll(async () => {
  await vendor.close();
  await recording.restore();
  if (seededConnectionIds.length > 0 || seededProviderIds.length > 0) {
    const owner = new Pool({ connectionString: OWNER_URL, max: 1 });
    try {
      if (seededConnectionIds.length > 0) {
        await owner.query(`DELETE FROM user_connections WHERE id = ANY($1::uuid[])`, [
          seededConnectionIds,
        ]);
      }
      if (seededProviderIds.length > 0) {
        await owner.query(`DELETE FROM connection_providers WHERE id = ANY($1::uuid[])`, [
          seededProviderIds,
        ]);
      }
    } finally {
      await owner.end();
    }
  }
});

/**
 * Per-test teardown: the adversarial attribute scan (ADR-0037 decision 6, the
 * spanAttributes suite's extension to this path) — EVERY attribute of EVERY
 * span is allowlisted, no egress span records an exception, and the material
 * these tests move appears nowhere. The fixture and telemetry go back to
 * baseline.
 */
afterEach(async () => {
  for (const span of recording.spans()) {
    for (const key of Object.keys(span.attributes)) {
      expect(EGRESS_SPAN_ATTRS, `${span.name} carried ${key}`).toContain(key);
    }
    expect(span.events.filter((e) => e.name === "exception")).toEqual([]);
    expect(JSON.stringify(span.attributes)).not.toMatch(/planted-|not-a-vendor-token/);
  }
  recording.reset();
  vendor.setModes({ tokenMode: "rotating", authorizeMode: "approve" });
  vendor.resetTokenCalls();
});

// ── Fixtures ─────────────────────────────────────────────────────────────────

const PLANTED_ACCESS = "delegated-planted-access-token";
const PLANTED_REFRESH = "delegated-planted-refresh-token";

async function makeProvider(
  overrides: Partial<ConnectionProvider> = {},
): Promise<ConnectionProvider> {
  return ConnectionProviderSchema.parse({
    id: randomUUID(),
    ref: "delegated-fixture",
    kind: "rest-delegated",
    displayName: "Delegated Fixture",
    authorizeEndpoint: `${vendor.issuer}/authorize`,
    tokenEndpoint: `${vendor.issuer}/token`,
    requestedScopes: [],
    apiOrigins: [vendor.issuer],
    tokenPlacement: { kind: "header-bearer" },
    env: "prod",
    // Sealed through the SAME custody the resolution opens them with — the
    // provider row holds sealed material, like every real row.
    clientIdMaterial: await credentialStore.seal(CLIENT_ID),
    clientSecretMaterial: await credentialStore.seal(CLIENT_SECRET),
    revision: 1,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  });
}

/** The provider cache fake — in-memory rows, keyed (id) and (ref, env). */
function cacheFor(...rows: ConnectionProvider[]) {
  return {
    get: (id: string) => rows.find((r) => r.id === id),
    getByRef: (ref: string, env: Env) => rows.find((r) => r.ref === ref && r.env === env),
    isLoaded: () => true,
  };
}

/** A static-secret resolver that would inject a marker if it were EVER
 * consulted on the delegated path — the no-static-fallback proof. */
const markerResolver: SecretResolver = {
  resolve: async () => ({
    value: "planted-static-secret-marker",
    injection: { kind: "header-bearer" },
  }),
  close: async () => {},
};

function makeApp(providers: ReturnType<typeof cacheFor>, opts: { wired?: boolean } = {}) {
  const config = {
    limits: { maxBodyBytes: 1024 * 1024, timeoutMs: VENDOR_TIMEOUT_MS },
    allowPrivate: true,
    extraBlockedCidrs: [] as EgressConfig["extraBlockedCidrs"],
    // The fixture vendor is http; the cleartext seam is a dev/test one.
    allowInsecureConnection: true,
  } as EgressConfig;
  const pool = createEgressPool(egressUrl(), { max: 4 });
  const delegatedStore = createSecretStore({ devMasterKey: kek });
  return buildApp({
    config,
    resolver: markerResolver,
    instructionKey: key,
    burnStore: null,
    delegated:
      opts.wired === false
        ? null
        : {
            pool,
            providers,
            credentialStore,
            delegatedStore,
            timeoutMs: VENDOR_TIMEOUT_MS,
            allowInsecureConnection: true,
          },
  });
}

const secret = Buffer.from("delegated-instruction-secret-0123456789abcdef", "utf8");
const key = deriveInstructionKey(secret);

/** Mint an instruction the way the edge mints it (the shared sign helpers'
 * shape), including the caller kind the strict schema requires. */
async function mint(claims: {
  origin: string;
  provider?: string;
  connection?: string;
  userOid?: string;
  userKind?: PrincipalKind;
  env?: Env;
  appId?: string;
  method?: string;
  path?: string;
}): Promise<string> {
  const requestId = randomUUID();
  const payload = {
    appId: claims.appId ?? "app-1",
    userOid: claims.userOid ?? `user-${randomUUID()}`,
    capability: "fetch" as const,
    origin: claims.origin,
    requestId,
    env: claims.env ?? ("prod" as Env),
    ...(claims.userKind ? { userKind: claims.userKind } : {}),
    ...(claims.method ? { method: claims.method } : {}),
    ...(claims.path !== undefined ? { path: claims.path } : {}),
    ...(claims.connection ? { connection: claims.connection } : {}),
    ...(claims.provider ? { provider: claims.provider } : {}),
  };
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256", typ: INSTRUCTION_JWT_TYP })
    .setJti(requestId)
    .setAudience(INSTRUCTION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("30s")
    .sign(key);
}

async function ownerQuery<T extends Record<string, unknown>>(
  sql: string,
  values: unknown[] = [],
): Promise<T[]> {
  const owner = new Pool({ connectionString: OWNER_URL, max: 1 });
  try {
    return (await owner.query<T>(sql, values)).rows;
  } finally {
    await owner.end();
  }
}

/** Seed one connection row (as the owner), material sealed under the KEK. */
async function seedConnection(opts: {
  providerId: string;
  providerRevision?: number;
  userOid?: string;
  env?: Env;
  /** Access-token expiry relative to now; negative = expired. */
  expiresInSec?: number;
  renewBeforeNext?: boolean;
  status?: "live" | "reconnect-needed" | "invalidated";
  tokens?: { access: string; refresh: string };
  grantedScopes?: string[];
}): Promise<{ id: string; userOid: string; env: Env }> {
  const delegated = createSecretStore({ devMasterKey: kek });
  const tokens = opts.tokens ?? { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH };
  const material = JSON.stringify(
    ConnectionMaterialSchema.parse({
      access: await delegated.seal(tokens.access),
      refresh: await delegated.seal(tokens.refresh),
    }),
  );
  const id = randomUUID();
  const userOid = opts.userOid ?? `user-${randomUUID()}`;
  const env = opts.env ?? "prod";
  const expiresInSec = opts.expiresInSec ?? 900;
  await ownerQuery(
    `INSERT INTO user_connections (id, "userOid", "providerId", "providerRevision", env, status,
        material, "grantedScopes", "grantedAt", "expiresAt", "renewBeforeNext", "pendingRetire",
        "lastRenewedAt", "createdAt", "updatedAt")
      VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8::jsonb, now(),
              now() + ($9 || ' seconds')::interval, $10, NULL, NULL, now(), now())`,
    [
      id,
      userOid,
      opts.providerId,
      opts.providerRevision ?? 1,
      env,
      opts.status ?? "live",
      material,
      JSON.stringify(opts.grantedScopes ?? []),
      String(expiresInSec),
      opts.renewBeforeNext ?? false,
    ],
  );
  seededConnectionIds.push(id);
  return { id, userOid, env };
}

/** Seed a raw provider row the CACHE would drop (the malformed-row case). */
async function seedMalformedProviderRow(ref: string, env: Env): Promise<string> {
  const id = randomUUID();
  await ownerQuery(
    `INSERT INTO connection_providers (id, ref, kind, "displayName", "authorizeEndpoint",
        "tokenEndpoint", "requestedScopes", "apiOrigins", "tokenPlacement", env,
        "clientIdMaterial", "clientSecretMaterial", revision, "createdAt", "updatedAt")
      VALUES ($1::uuid, $2, 'rest-delegated', 'Broken', 'https://vendor.example/authorize',
        'https://vendor.example/token', '[]'::jsonb, '[]'::jsonb, '{"kind":"header-bearer"}', $3,
        'material-a', 'material-b', 1, now(), now())`,
    [id, ref, env],
  );
  seededProviderIds.push(id);
  return id;
}

/** Read the connection row back through the egress identity — the stored-row
 * parse, exactly what the resolution reads. */
async function readRow(
  userOid: string,
  providerId: string,
  env: Env,
): Promise<UserConnection | null> {
  const pool = new Pool({ connectionString: egressUrl(), max: 1 });
  try {
    const { rows } = await pool.query<Record<string, unknown>>(
      `SELECT id, "userOid", "providerId", "providerRevision", env, status, material,
              "grantedScopes", "grantedAt", "expiresAt", "renewBeforeNext", "pendingRetire",
              "lastRenewedAt", "createdAt", "updatedAt"
         FROM user_connections WHERE "userOid" = $1 AND "providerId" = $2::uuid AND env = $3`,
      [userOid, providerId, env],
    );
    return rows[0] ? userConnectionFromPg(rows[0] as never) : null;
  } finally {
    await pool.end();
  }
}

/** Drive the fixture's real code flow once; the tokens it mints are real. */
async function driveGrant(
  v: { issuer: string } = vendor,
  scope?: string,
): Promise<{ access: string; refresh: string }> {
  const verifier = newCodeVerifier();
  const auth = await requestAuthorizationCode(v, {
    redirectUri: REDIRECT_URI,
    challenge: s256CodeChallenge(verifier),
    scope,
    clientId: CLIENT_ID,
  });
  expect(auth.code).toBeTruthy();
  const res = await exchangeAuthorizationCode(v, auth.code as string, {
    verifier,
    redirectUri: REDIRECT_URI,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  });
  expect(res.ok).toBe(true);
  return {
    access: res.body.access_token as string,
    refresh: res.body.refresh_token as string,
  };
}

function refreshPresentations(): number {
  return vendor.tokenCalls().filter((c) => c.grantType === "refresh_token").length;
}

/** The fixture's API-destination echo, read back through the proxied response. */
function echoedToken(res: { payload: string }): {
  placement: string;
  headerName: string | null;
  token: string | null;
} {
  return JSON.parse(res.payload) as {
    placement: string;
    headerName: string | null;
    token: string | null;
  };
}

/**
 * A scripted API destination: records every request it receives (the
 * dispatch-before-refusal evidence the fixture's token log cannot give — it
 * only sees the OAuth surface) and answers with a scripted status/headers/body.
 */
interface ScriptedApi {
  origin: string;
  requests(): { method: string; path: string | undefined; authorization: string | undefined }[];
  close(): Promise<void>;
}

function scriptedApi(
  respond: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<ScriptedApi> {
  const log: { method: string; path: string | undefined; authorization: string | undefined }[] = [];
  const server: Server = createServer((req, res) => {
    log.push({
      method: req.method ?? "",
      path: req.url,
      authorization: req.headers["authorization"],
    });
    respond(req, res);
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        requests: () => [...log],
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

async function proxyCall(
  app: ReturnType<typeof buildApp>,
  token: string,
  target: string,
  method = "GET",
): Promise<{
  statusCode: number;
  payload: string;
  headers: Record<string, unknown>;
  json(): unknown;
}> {
  const res = await app.inject({
    method: "POST",
    url: "/proxy",
    headers: {
      [INSTRUCTION_HEADER]: token,
      [TARGET_HEADER]: target,
      [METHOD_HEADER]: method,
    },
  });
  return {
    statusCode: res.statusCode,
    payload: res.payload,
    headers: res.headers,
    json: () => res.json(),
  };
}

// ── The suite ────────────────────────────────────────────────────────────────

describe("delegated call — token placement", () => {
  it("Bearer default: the fresh row's token reaches the fixture's echo, nothing renews", async () => {
    if (!ok) return;
    const provider = await makeProvider();
    const seeded = await seedConnection({
      providerId: provider.id,
      tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
    });
    const app = makeApp(cacheFor(provider));
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: seeded.userOid,
        userKind: "user",
        path: "/api/echo",
      });
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      expect(res.statusCode).toBe(200);
      expect(res.headers[OUTCOME_HEADER]).toBe("ok");
      const echo = echoedToken(res);
      expect(echo.placement).toBe("header-bearer");
      expect(echo.headerName).toBe("authorization");
      expect(echo.token).toBe(PLANTED_ACCESS);
      // Not renewed: the token was fresh — the vendor saw no token call.
      expect(refreshPresentations()).toBe(0);
      // The row is untouched.
      const row = await readRow(seeded.userOid, provider.id, "prod");
      expect(row?.status).toBe("live");
      expect(row?.renewBeforeNext).toBe(false);
    } finally {
      await app.close();
    }
  });

  it("named-header placement: the token rides the provider's configured header verbatim", async () => {
    if (!ok) return;
    const provider = await makeProvider({
      tokenPlacement: { kind: "header", name: NAMED_HEADER },
    });
    const seeded = await seedConnection({
      providerId: provider.id,
      tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
    });
    const app = makeApp(cacheFor(provider));
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: seeded.userOid,
        userKind: "user",
        path: "/api/echo",
      });
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      expect(res.statusCode).toBe(200);
      const echo = echoedToken(res);
      expect(echo.placement).toBe("header");
      expect(echo.headerName).toBe(NAMED_HEADER);
      expect(echo.token).toBe(PLANTED_ACCESS);
    } finally {
      await app.close();
    }
  });

  it("the app cannot smuggle or override the credential header", async () => {
    if (!ok) return;
    const provider = await makeProvider();
    const seeded = await seedConnection({
      providerId: provider.id,
      tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
    });
    const app = makeApp(cacheFor(provider));
    try {
      const requestId = randomUUID();
      // Mint directly so the request can ALSO carry an authorization header —
      // the request safelist drops it before egress; the injected token is the
      // only one the vendor may see.
      const instruction = await new SignJWT({
        appId: "app-1",
        userOid: seeded.userOid,
        userKind: "user",
        capability: "fetch",
        origin: vendor.issuer,
        requestId,
        env: "prod",
        provider: provider.ref,
        path: "/api/echo",
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
          [INSTRUCTION_HEADER]: instruction,
          [TARGET_HEADER]: `${vendor.issuer}/api/echo`,
          [METHOD_HEADER]: "GET",
          authorization: "Bearer planted-app-supplied-token",
        },
      });
      expect(res.statusCode).toBe(200);
      const echo = echoedToken(res);
      expect(echo.token).toBe(PLANTED_ACCESS);
      expect(res.payload).not.toContain("planted-app-supplied-token");
    } finally {
      await app.close();
    }
  });
});

describe("delegated call — refusals before dispatch", () => {
  it("no connection row: 403 connection_required with provider metadata and NO vendor traffic", async () => {
    if (!ok) return;
    const api = await scriptedApi((_req, res) => {
      res.statusCode = 200;
      res.end("SHOULD-NOT-DISPATCH");
    });
    try {
      const provider = await makeProvider({ apiOrigins: [api.origin] });
      const caller = `user-${randomUUID()}`; // never seeded — no connection
      const app = makeApp(cacheFor(provider));
      try {
        const instruction = await mint({
          origin: api.origin,
          provider: provider.ref,
          userOid: caller,
          userKind: "user",
        });
        const res = await proxyCall(app, instruction, `${api.origin}/anything`);
        expect(res.statusCode).toBe(403);
        expect(res.json()).toEqual({
          code: "connection_required",
          message: "connect the provider account to continue",
          provider: { ref: provider.ref, displayName: provider.displayName },
        });
        // The ledger label is the NEW one — distinguishable from refusal.
        expect(res.headers[OUTCOME_HEADER]).toBe("connection_required");
        // Dispatch-before-refusal: the vendor was never dialed, on either
        // surface — no API call, no token call.
        expect(api.requests()).toEqual([]);
        expect(vendor.tokenCalls()).toEqual([]);
      } finally {
        await app.close();
      }
    } finally {
      await api.close();
    }
  });

  it("a dead (invalidated) row and a reconnect-needed row refuse without vendor traffic", async () => {
    if (!ok) return;
    const api = await scriptedApi((_req, res) => {
      res.statusCode = 200;
      res.end("SHOULD-NOT-DISPATCH");
    });
    try {
      const provider = await makeProvider({ apiOrigins: [api.origin] });
      const dead = await seedConnection({
        providerId: provider.id,
        status: "invalidated",
        tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
      });
      const reconnect = await seedConnection({
        providerId: provider.id,
        status: "reconnect-needed",
        tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
      });
      const app = makeApp(cacheFor(provider));
      try {
        for (const seeded of [dead, reconnect]) {
          const instruction = await mint({
            origin: api.origin,
            provider: provider.ref,
            userOid: seeded.userOid,
            userKind: "user",
          });
          const res = await proxyCall(app, instruction, `${api.origin}/x`);
          expect(res.statusCode).toBe(403);
          expect(res.json()).toMatchObject({ code: "connection_required" });
        }
        expect(api.requests()).toEqual([]);
        expect(vendor.tokenCalls()).toEqual([]);
      } finally {
        await app.close();
      }
    } finally {
      await api.close();
    }
  });

  it("an anonymous caller with a LIVE connection: refused by kind, row untouched", async () => {
    if (!ok) return;
    const api = await scriptedApi((_req, res) => {
      res.statusCode = 200;
      res.end("SHOULD-NOT-DISPATCH");
    });
    try {
      const provider = await makeProvider({ apiOrigins: [api.origin] });
      await seedConnection({
        providerId: provider.id,
        userOid: "anon", // the edge's anonymous sentinel
        tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
      });
      const app = makeApp(cacheFor(provider));
      try {
        const instruction = await mint({
          origin: api.origin,
          provider: provider.ref,
          userOid: "anon",
          userKind: "anon",
        });
        const res = await proxyCall(app, instruction, `${api.origin}/x`);
        expect(res.statusCode).toBe(403);
        expect(res.json()).toEqual({
          code: "connection_required",
          message: "connect the provider account to continue",
          provider: { ref: provider.ref, displayName: provider.displayName },
        });
        // The live row the anonymous caller can never use is untouched — the
        // refusal must not mutate (or leak) anything.
        const row = await readRow("anon", provider.id, "prod");
        expect(row?.status).toBe("live");
        expect(api.requests()).toEqual([]);
        expect(vendor.tokenCalls()).toEqual([]);
      } finally {
        await app.close();
      }
    } finally {
      await api.close();
    }
  });

  it("a shared-password pseudonym with a LIVE connection: refused by kind", async () => {
    if (!ok) return;
    const api = await scriptedApi((_req, res) => {
      res.statusCode = 200;
      res.end("SHOULD-NOT-DISPATCH");
    });
    try {
      const provider = await makeProvider({ apiOrigins: [api.origin] });
      const pseudonym = "pw_a1B2c3D4e5F6";
      await seedConnection({
        providerId: provider.id,
        userOid: pseudonym,
        tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
      });
      const app = makeApp(cacheFor(provider));
      try {
        const instruction = await mint({
          origin: api.origin,
          provider: provider.ref,
          userOid: pseudonym,
          userKind: "password",
        });
        const res = await proxyCall(app, instruction, `${api.origin}/x`);
        expect(res.statusCode).toBe(403);
        expect(res.json()).toMatchObject({ code: "connection_required" });
        expect(api.requests()).toEqual([]);
        // The pseudonym's row is untouched.
        const row = await readRow(pseudonym, provider.id, "prod");
        expect(row?.status).toBe("live");
      } finally {
        await app.close();
      }
    } finally {
      await api.close();
    }
  });

  it("never falls back: another user's connection, a static secret, or an unauthenticated call", async () => {
    if (!ok) return;
    const api = await scriptedApi((_req, res) => {
      res.statusCode = 200;
      res.end("SHOULD-NOT-DISPATCH");
    });
    try {
      const provider = await makeProvider({ apiOrigins: [api.origin] });
      // User A holds a live connection; user B calls the same provider.
      await seedConnection({
        providerId: provider.id,
        userOid: "user-alice",
        tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
      });
      const app = makeApp(cacheFor(provider));
      try {
        const instruction = await mint({
          origin: api.origin,
          provider: provider.ref,
          userOid: "user-bob", // no connection of their own
          userKind: "user",
        });
        const res = await proxyCall(app, instruction, `${api.origin}/x`);
        expect(res.statusCode).toBe(403);
        expect(res.json()).toMatchObject({ code: "connection_required" });
        // Nothing was dispatched at all — so nothing could have fallen back:
        // not to Alice's row, not to the marker resolver's static secret, not
        // to an unauthenticated vendor call. Alice's row still works.
        expect(api.requests()).toEqual([]);
        expect(vendor.tokenCalls()).toEqual([]);
        const alice = await readRow("user-alice", provider.id, "prod");
        expect(alice?.status).toBe("live");

        // And the static secret behind the same app is never consulted: the
        // marker resolver would have planted it on any dispatch.
        const keylessInstruction = await mint({
          origin: api.origin,
          provider: provider.ref,
          userOid: "user-bob",
          userKind: "user",
        });
        await proxyCall(app, keylessInstruction, `${api.origin}/y`);
        expect(api.requests()).toEqual([]);
      } finally {
        await app.close();
      }
    } finally {
      await api.close();
    }
  });

  it("a genuine signed-in user is served by KIND — the app's visibility is not in the contract", async () => {
    if (!ok) return;
    // Criterion 21's eligibility clause: a genuine signed-in principal of a
    // password-visible app remains eligible. Egress never sees the app's
    // visibility — the instruction contract carries the caller's KIND and
    // nothing about the app (a strict parse would refuse such a field) — so
    // an app-visibility shortcut is not representable; the served call below
    // is the positive half, and the shared schema test pins the structural
    // half.
    const provider = await makeProvider();
    const seeded = await seedConnection({
      providerId: provider.id,
      userOid: "user-signed-in",
      tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
    });
    const app = makeApp(cacheFor(provider));
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: seeded.userOid,
        userKind: "user",
        path: "/api/echo",
      });
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      expect(res.statusCode).toBe(200);
      expect(echoedToken(res).token).toBe(PLANTED_ACCESS);
    } finally {
      await app.close();
    }
  });
});

describe("delegated call — provider state", () => {
  it("a deleted provider: 503 provider_unavailable with {ref} only", async () => {
    if (!ok) return;
    // The cache serves nothing (deletion is a hard DELETE — the next reconcile
    // drops the entry) and the row is gone from the table.
    const app = makeApp(cacheFor());
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: "gone-provider",
        userOid: "user-1",
        userKind: "user",
      });
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      expect(res.statusCode).toBe(503);
      expect(res.json()).toEqual({
        code: "provider_unavailable",
        message: "provider is currently unavailable",
        provider: { ref: "gone-provider" },
      });
      expect(res.headers[OUTCOME_HEADER]).toBe("refusal");
      expect(vendor.tokenCalls()).toEqual([]);
    } finally {
      await app.close();
    }
  });

  it("a revision-advanced provider (the row's stamp behind the cache): 503 provider_unavailable", async () => {
    if (!ok) return;
    const provider = await makeProvider();
    await seedConnection({
      providerId: provider.id,
      userOid: "user-rev",
      tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
    });
    // A sensitive edit bumped the provider to revision 2; the connection row
    // still carries its consent-time stamp of 1. The cache holds the CURRENT
    // row (revision 2) — resolution refuses on the stamp.
    const edited = { ...provider, revision: 2 };
    const app = makeApp(cacheFor(edited));
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: "user-rev",
        userKind: "user",
      });
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      expect(res.statusCode).toBe(503);
      expect(res.json()).toMatchObject({ code: "provider_unavailable" });
      expect(vendor.tokenCalls()).toEqual([]);
    } finally {
      await app.close();
    }
  });

  it("a malformed provider row (cache-dropped, probe finds it): 502 provider_misconfigured, opaque", async () => {
    if (!ok) return;
    const ref = "delegated-broken";
    await seedMalformedProviderRow(ref, "prod");
    const app = makeApp(cacheFor());
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: ref,
        userOid: "user-1",
        userKind: "user",
      });
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      expect(res.statusCode).toBe(502);
      // Opaque: the body is the fixed pair alone — no provider metadata, no
      // row content, no vendor content.
      expect(res.json()).toEqual({
        code: "provider_misconfigured",
        message: "provider is misconfigured — administrator action required",
      });
      expect(res.headers[OUTCOME_HEADER]).toBe("refusal");
      expect(vendor.tokenCalls()).toEqual([]);
    } finally {
      await app.close();
    }
  });

  it("a target origin outside the provider's approved destinations never receives the token", async () => {
    if (!ok) return;
    const api = await scriptedApi((_req, res) => {
      res.statusCode = 200;
      res.end("SHOULD-NOT-DISPATCH");
    });
    try {
      // The provider's destinations name the FIXTURE origin; the edge (in this
      // construction) authorized the scripted one. The re-check refuses
      // before any dispatch — the token cannot ride to a non-destination.
      const provider = await makeProvider();
      await seedConnection({
        providerId: provider.id,
        userOid: "user-orig",
        tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
      });
      const app = makeApp(cacheFor(provider));
      try {
        const instruction = await mint({
          origin: api.origin,
          provider: provider.ref,
          userOid: "user-orig",
          userKind: "user",
        });
        const res = await proxyCall(app, instruction, `${api.origin}/x`);
        expect(res.statusCode).toBe(503);
        expect(res.json()).toMatchObject({ code: "provider_unavailable" });
        expect(api.requests()).toEqual([]);
      } finally {
        await app.close();
      }
    } finally {
      await api.close();
    }
  });
});

describe("delegated call — expiry-driven renewal", () => {
  it("expired token + healthy connection: renews before dispatch, invisible to the caller (rotating)", async () => {
    if (!ok) return;
    const provider = await makeProvider();
    const tokens = await driveGrant(vendor, "email");
    const seeded = await seedConnection({
      providerId: provider.id,
      tokens,
      grantedScopes: ["email"],
      expiresInSec: -60, // expired
    });
    const app = makeApp(cacheFor(provider));
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: seeded.userOid,
        userKind: "user",
        path: "/api/echo",
      });
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      // The call just succeeds — the renewal is invisible.
      expect(res.statusCode).toBe(200);
      const echo = echoedToken(res);
      expect(echo.placement).toBe("header-bearer");

      // The vendor saw exactly one refresh presentation, BEFORE the dispatch.
      expect(refreshPresentations()).toBe(1);
      // The dispatched token is the one renewal stored and sealed — not the
      // expired one.
      const row = await readRow(seeded.userOid, provider.id, "prod");
      expect(row?.status).toBe("live");
      const fresh = ConnectionMaterialSchema.parse(JSON.parse(row?.material ?? "{}"));
      const delegated = createSecretStore({ devMasterKey: kek });
      const freshToken = await delegated.open(fresh.access);
      expect(echo.token).toBe(freshToken);
      expect(echo.token).not.toBe(tokens.access);
      // The rotation's replacement is in the row; the old material is
      // ledger-marked for the sweep.
      expect(row?.pendingRetire).not.toBeNull();
      expect(row?.renewBeforeNext).toBe(false);
    } finally {
      await app.close();
    }
  });

  it("expired token, non-rotating vendor: the refresh material is retained across the renewal", async () => {
    if (!ok) return;
    vendor.setModes({ tokenMode: "non-rotating" });
    const provider = await makeProvider();
    const tokens = await driveGrant(vendor, "email");
    const seeded = await seedConnection({
      providerId: provider.id,
      tokens,
      grantedScopes: ["email"],
      expiresInSec: -60,
    });
    const app = makeApp(cacheFor(provider));
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: seeded.userOid,
        userKind: "user",
        path: "/api/echo",
      });
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      expect(res.statusCode).toBe(200);
      const row = await readRow(seeded.userOid, provider.id, "prod");
      const fresh = ConnectionMaterialSchema.parse(JSON.parse(row?.material ?? "{}"));
      // The access material swapped; the refresh reference retained the SAME
      // sealed string (the vendor never rotates it, and the renewer keeps it).
      const delegated = createSecretStore({ devMasterKey: kek });
      expect(await delegated.open(fresh.refresh)).toBe(tokens.refresh);
      expect(await delegated.open(fresh.access)).not.toBe(tokens.access);
      expect(row?.pendingRetire).toBeNull();
    } finally {
      await app.close();
    }
  });

  it("dev tier: dev and prod connections of one ref never see each other", async () => {
    if (!ok) return;
    // Dev-tier delegation is keyed by the dev token's developer identity
    // in the dev environment — the env partition rides the instruction's env.
    // The same ref is configured in BOTH tiers (two provider rows, distinct
    // ids); the dev caller's dispatch must use the DEV connection's token.
    const prodProvider = await makeProvider({ ref: "delegated-partition" });
    const devProvider = await makeProvider({ ref: "delegated-partition", env: "dev" });
    const prodTokens = await driveGrant(vendor, "email");
    const devTokens = await driveGrant(vendor, "email");
    await seedConnection({
      providerId: prodProvider.id,
      userOid: "developer-1",
      tokens: prodTokens,
      grantedScopes: ["email"],
      expiresInSec: 900,
    });
    const devSeeded = await seedConnection({
      providerId: devProvider.id,
      userOid: "developer-1",
      env: "dev",
      tokens: devTokens,
      grantedScopes: ["email"],
      expiresInSec: -60, // expired — the dev call must renew, proving the row used
    });
    const app = makeApp(cacheFor(prodProvider, devProvider));
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: devProvider.ref,
        userOid: "developer-1",
        userKind: "dev",
        env: "dev",
        path: "/api/echo",
      });
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      expect(res.statusCode).toBe(200);
      // The renewal ran (the dev row was expired) — the dev row was the one
      // used, and the dispatched token is the dev connection's fresh token,
      // never the prod connection's.
      expect(refreshPresentations()).toBe(1);
      const echo = echoedToken(res);
      const row = await readRow(devSeeded.userOid, devProvider.id, "dev");
      const delegated = createSecretStore({ devMasterKey: kek });
      const fresh = ConnectionMaterialSchema.parse(JSON.parse(row?.material ?? "{}"));
      expect(echo.token).toBe(await delegated.open(fresh.access));
      expect(echo.token).not.toBe(prodTokens.access);
      // The prod row is untouched by the dev call — the dev renewal never
      // reached it.
      const prodRow = await readRow("developer-1", prodProvider.id, "prod");
      expect(prodRow?.renewBeforeNext).toBe(false);

      // And a dev-kind caller asking in the PROD tier resolves the PROD
      // connection — the keys never cross in either direction: the
      // dispatched token is the prod row's, and no further renewal ran.
      vendor.resetTokenCalls();
      const prodInstruction = await mint({
        origin: vendor.issuer,
        provider: prodProvider.ref,
        userOid: "developer-1",
        userKind: "dev",
        env: "prod",
        path: "/api/echo",
      });
      const prodRes = await proxyCall(app, prodInstruction, `${vendor.issuer}/api/echo`);
      expect(prodRes.statusCode).toBe(200);
      expect(refreshPresentations()).toBe(0);
      expect(echoedToken(prodRes).token).toBe(prodTokens.access);
    } finally {
      await app.close();
    }
  });
});

describe("delegated call — the renewal failure taxonomy through the proxy", () => {
  it("temporary failure (the vendor hangs): 502 upstream_error, connection preserved", async () => {
    if (!ok) return;
    const provider = await makeProvider();
    const seeded = await seedConnection({
      providerId: provider.id,
      tokens: await driveGrant(vendor, "email"),
      grantedScopes: ["email"],
      expiresInSec: -60,
    });
    // Hang only AFTER the grant is driven — the fault mode applies to the
    // renewal, never to the seeding.
    vendor.setModes({ tokenMode: "hang" });
    const app = makeApp(cacheFor(provider));
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: seeded.userOid,
        userKind: "user",
        path: "/api/echo",
      });
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      expect(res.statusCode).toBe(502);
      expect(res.json()).toEqual({
        code: "upstream_error",
        message: "delegated credential unavailable",
      });
      // The LEDGER outcome is `error` — the existing class, not a consent word.
      expect(res.headers[OUTCOME_HEADER]).toBe("error");
      // The connection is preserved: the row stands, and a later request may
      // try again (no consent asked).
      const row = await readRow(seeded.userOid, provider.id, "prod");
      expect(row?.status).toBe("live");
      expect(row?.renewBeforeNext).toBe(false);
      expect(refreshPresentations()).toBe(1);
    } finally {
      await app.close();
    }
  });

  it("uncertain rotation: 403 connection_required — the caller must reconnect", async () => {
    if (!ok) return;
    const provider = await makeProvider();
    const seeded = await seedConnection({
      providerId: provider.id,
      tokens: await driveGrant(vendor, "email"),
      grantedScopes: ["email"],
      expiresInSec: -60,
    });
    // The consumed-then-drop fault applies to the RENEWAL, never to the
    // seeding grant above.
    vendor.setModes({ tokenMode: "consumed-then-drop" });
    const app = makeApp(cacheFor(provider));
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: seeded.userOid,
        userKind: "user",
        path: "/api/echo",
      });
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      expect(res.statusCode).toBe(403);
      expect(res.json()).toMatchObject({ code: "connection_required" });
      expect(res.headers[OUTCOME_HEADER]).toBe("connection_required");
      // The renewer flipped the row to reconnect-needed — the next consent is
      // a fresh explicit Connect.
      const row = await readRow(seeded.userOid, provider.id, "prod");
      expect(row?.status).toBe("reconnect-needed");
    } finally {
      await app.close();
    }
  });

  it("admin_action (invalid_client): 502 provider_misconfigured — administrator action, opaque", async () => {
    if (!ok) return;
    const tokenServer = await scriptedApi((_req, res) => {
      res.statusCode = 401;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: "invalid_client" }));
    });
    try {
      const provider = await makeProvider({ tokenEndpoint: `${tokenServer.origin}/token` });
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: await driveGrant(vendor, "email"),
        grantedScopes: ["email"],
        expiresInSec: -60,
      });
      const app = makeApp(cacheFor(provider));
      try {
        const instruction = await mint({
          origin: vendor.issuer,
          provider: provider.ref,
          userOid: seeded.userOid,
          userKind: "user",
          path: "/api/echo",
        });
        const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
        expect(res.statusCode).toBe(502);
        expect(res.json()).toEqual({
          code: "provider_misconfigured",
          message: "provider is misconfigured — administrator action required",
        });
        // The row is NOT the problem — it stands untouched.
        const row = await readRow(seeded.userOid, provider.id, "prod");
        expect(row?.status).toBe("live");
      } finally {
        await app.close();
      }
    } finally {
      await tokenServer.close();
    }
  });
});

describe("delegated call — pre-expiry vendor 401", () => {
  /** The scripted 401 the vendor "should not have sent" — the app's own
   * vendor-side credential problem, never platform consent status. */
  const NOT_AUTHORIZED_BODY = JSON.stringify({ error: "vendor says no", detail: "fixed-401" });

  function rejectingApi(): Promise<ScriptedApi> {
    return scriptedApi((_req, res) => {
      res.statusCode = 401;
      res.setHeader("content-type", "application/json");
      res.end(NOT_AUTHORIZED_BODY);
    });
  }

  async function pollFlag(userOid: string, providerId: string, env: Env): Promise<boolean> {
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const row = await readRow(userOid, providerId, env);
      if (row?.renewBeforeNext === true) return true;
      await new Promise((r) => setTimeout(r, 50));
    }
    return false;
  }

  it("rotating: the 401 passes through byte-unchanged, no replay, and the flag is set", async () => {
    if (!ok) return;
    const api = await rejectingApi();
    try {
      const provider = await makeProvider({ apiOrigins: [api.origin] });
      const tokens = await driveGrant(vendor, "email");
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens, // pre-expiry — nothing is due
        grantedScopes: ["email"],
        expiresInSec: 900,
      });
      const app = makeApp(cacheFor(provider));
      try {
        const instruction = await mint({
          origin: api.origin,
          provider: provider.ref,
          userOid: seeded.userOid,
          userKind: "user",
          method: "GET",
          path: "/v1/things",
        });
        const res = await proxyCall(app, instruction, `${api.origin}/v1/things`);
        // BYTE-UNCHANGED passthrough: the vendor's status, body, and
        // content-type survive the proxy untouched.
        expect(res.statusCode).toBe(401);
        expect(res.payload).toBe(NOT_AUTHORIZED_BODY);
        expect(res.headers["content-type"]).toContain("application/json");
        // No replay: the vendor saw the call exactly once.
        expect(api.requests()).toHaveLength(1);
        // No renewal happened on the way in — the token was not expired.
        expect(refreshPresentations()).toBe(0);
        // The flag is set (fire-and-forget — poll briefly).
        expect(await pollFlag(seeded.userOid, provider.id, "prod")).toBe(true);
        // The row is otherwise untouched and still live.
        const row = await readRow(seeded.userOid, provider.id, "prod");
        expect(row?.status).toBe("live");
        expect(row?.material).toBeTruthy();
      } finally {
        await app.close();
      }
    } finally {
      await api.close();
    }
  });

  it("both rotation modes: the NEXT request renews before dispatch, and the fresh token dispatches", async () => {
    if (!ok) return;
    for (const tokenMode of ["rotating", "non-rotating"] as const) {
      vendor.setModes({ tokenMode });
      vendor.resetTokenCalls();
      const api = await scriptedApi((_req, res) => {
        res.statusCode = 200;
        res.end("ok-after-renewal");
      });
      try {
        const provider = await makeProvider({ apiOrigins: [api.origin], ref: "renew-before-next" });
        const tokens = await driveGrant(vendor, "email");
        const seeded = await seedConnection({
          providerId: provider.id,
          tokens,
          grantedScopes: ["email"],
          expiresInSec: 900, // NOT expired
          renewBeforeNext: true, // the pre-expiry-401 flag — renewal short-circuits expiry
        });
        const app = makeApp(cacheFor(provider));
        try {
          const instruction = await mint({
            origin: api.origin,
            provider: provider.ref,
            userOid: seeded.userOid,
            userKind: "user",
          });
          const res = await proxyCall(app, instruction, `${api.origin}/v1/x`);
          expect(res.statusCode).toBe(200);
          // The renewal ran BEFORE the dispatch, under both rotation habits.
          expect(refreshPresentations()).toBe(1);
          // The dispatched token is the fresh one.
          const row = await readRow(seeded.userOid, provider.id, "prod");
          expect(row?.renewBeforeNext).toBe(false);
          const delegated = createSecretStore({ devMasterKey: kek });
          const fresh = ConnectionMaterialSchema.parse(JSON.parse(row?.material ?? "{}"));
          if (tokenMode === "non-rotating") {
            // Retained refresh material — the same sealed string.
            expect(fresh.refresh).toBeTruthy();
          }
          expect(await delegated.open(fresh.access)).not.toBe(tokens.access);
        } finally {
          await app.close();
        }
      } finally {
        await api.close();
      }
    }
  });
});

describe("delegated call — late results cannot resurrect", () => {
  it("a row invalidated DURING renewal behaves as dead: no dispatch, row not overwritten", async () => {
    if (!ok) return;
    // The scripted token endpoint invalidates the row WHILE the refresh call
    // is in flight, then answers with fresh tokens. The renewer's CAS (WHERE
    // material = as-read AND status = 'live') must lose; the resolution's
    // post-renewal re-check must then refuse — the fresh token is never
    // injected onto a dead row.
    const api = await scriptedApi((_req, res) => {
      res.statusCode = 200;
      res.end("SHOULD-NOT-DISPATCH");
    });
    let invalidated = false;
    let rowId = "";
    let staleMaterial = "";
    const tokenServer = await scriptedApi((_req, res) => {
      const respond = () => {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            access_token: "a".repeat(43),
            token_type: "Bearer",
            expires_in: 900,
            refresh_token: "r".repeat(43),
          }),
        );
      };
      if (invalidated) return respond();
      invalidated = true;
      void ownerQuery(
        `UPDATE user_connections SET status = 'invalidated' WHERE id = $1 AND "material" = $2`,
        [rowId, staleMaterial],
      ).then(respond);
    });
    try {
      const provider = await makeProvider({
        apiOrigins: [api.origin],
        tokenEndpoint: `${tokenServer.origin}/token`,
      });
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: await driveGrant(vendor, "email"),
        grantedScopes: ["email"],
        expiresInSec: -60,
      });
      rowId = seeded.id;
      const before = await readRow(seeded.userOid, provider.id, "prod");
      staleMaterial = String(before?.material);
      const app = makeApp(cacheFor(provider));
      try {
        const instruction = await mint({
          origin: api.origin,
          provider: provider.ref,
          userOid: seeded.userOid,
          userKind: "user",
        });
        const res = await proxyCall(app, instruction, `${api.origin}/x`);
        // The renewal answered reconnect-shaped, the re-check saw the dead
        // row, and the call was refused as a consent problem — no dispatch.
        expect(res.statusCode).toBe(403);
        expect(res.json()).toMatchObject({ code: "connection_required" });
        expect(api.requests()).toEqual([]);
        // The dead row was not resurrected or overwritten: status and
        // material are exactly as the invalidation left them.
        const after = await readRow(seeded.userOid, provider.id, "prod");
        expect(after?.status).toBe("invalidated");
        expect(after?.material).toBe(staleMaterial);
      } finally {
        await app.close();
      }
    } finally {
      await tokenServer.close();
      await api.close();
    }
  });
});

describe("delegated call — telemetry (ADR-0037)", () => {
  it("the resolution span records the bounded outcome word, the provider ref, and no token", async () => {
    if (!ok) return;
    const provider = await makeProvider();
    const seeded = await seedConnection({
      providerId: provider.id,
      tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
    });
    const app = makeApp(cacheFor(provider));
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: seeded.userOid,
        userKind: "user",
        path: "/api/echo",
      });
      await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);

      const resolutions = recording.spans().filter((s) => s.name === SPAN_EGRESS_RESOLUTION);
      expect(resolutions).toHaveLength(1);
      const span = resolutions[0]!;
      expect(span.attributes["helix.outcome"]).toBe("resolved");
      expect(span.attributes["helix.provider_ref"]).toBe(provider.ref);
      expect(span.attributes["helix.env"]).toBe("prod");
      // The dispatched token value appears nowhere on ANY span.
      const all = JSON.stringify(recording.spans().map((s) => s.attributes));
      expect(all).not.toContain(PLANTED_ACCESS);
      expect(all).not.toContain(PLANTED_REFRESH);
    } finally {
      await app.close();
    }
  });

  it("a renewed dispatch marks `refreshed`; a refusal marks its vocabulary word", async () => {
    if (!ok) return;
    const provider = await makeProvider();
    const seeded = await seedConnection({
      providerId: provider.id,
      tokens: await driveGrant(vendor, "email"),
      grantedScopes: ["email"],
      expiresInSec: -60,
    });
    const app = makeApp(cacheFor(provider));
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: seeded.userOid,
        userKind: "user",
        path: "/api/echo",
      });
      await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      const resolutions = recording.spans().filter((s) => s.name === SPAN_EGRESS_RESOLUTION);
      expect(resolutions[0]?.attributes["helix.outcome"]).toBe("refreshed");
      // The renewal span ran within the resolution's, with its own word.
      const renewals = recording.spans().filter((s) => s.name === SPAN_EGRESS_RENEWAL);
      expect(renewals[0]?.attributes["helix.outcome"]).toBe("refreshed");

      // A refusal path: the proxy span's ledger label is the NEW one.
      vendor.resetTokenCalls();
      const stranger = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: `user-${randomUUID()}`,
        userKind: "user",
        path: "/api/echo",
      });
      const refused = await proxyCall(app, stranger, `${vendor.issuer}/api/echo`);
      expect(refused.headers[OUTCOME_HEADER]).toBe("connection_required");
      const refusedResolutions = recording
        .spans()
        .filter((s) => s.name === SPAN_EGRESS_RESOLUTION)
        .at(-1);
      expect(refusedResolutions?.attributes["helix.outcome"]).toBe("connection_required");
      // The proxy span still grades 4xx as UNSET status — a refusal is this
      // service working — but carries the outcome label.
      const refusedProxy = recording
        .spans()
        .filter((s) => s.name === SPAN_EGRESS_PROXY)
        .at(-1);
      expect(refusedProxy?.attributes["helix.outcome"]).toBe("connection_required");
      expect(refusedProxy?.attributes["helix.credential_source"]).toBeUndefined();
    } finally {
      await app.close();
    }
  });

  it("a successful delegated dispatch stamps credential_source: delegated on the proxy span", async () => {
    if (!ok) return;
    const provider = await makeProvider();
    const seeded = await seedConnection({
      providerId: provider.id,
      tokens: { access: PLANTED_ACCESS, refresh: PLANTED_REFRESH },
    });
    const app = makeApp(cacheFor(provider));
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: seeded.userOid,
        userKind: "user",
        path: "/api/echo",
      });
      await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      const proxySpan = recording
        .spans()
        .filter((s) => s.name === SPAN_EGRESS_PROXY)
        .at(-1);
      expect(proxySpan?.attributes["helix.credential_source"]).toBe("delegated");
      expect(proxySpan?.attributes["helix.provider_ref"]).toBe(provider.ref);
      // A delegated call carries NO connection (secret) attribute.
      expect(proxySpan?.attributes["helix.connection"]).toBeUndefined();
    } finally {
      await app.close();
    }
  });
});

describe("delegated call — unwired (fail closed)", () => {
  it("a delegated instruction with no resolution wired: opaque 502, nothing dialed", async () => {
    if (!ok) return;
    const provider = await makeProvider();
    const app = makeApp(cacheFor(provider), { wired: false });
    try {
      const instruction = await mint({
        origin: vendor.issuer,
        provider: provider.ref,
        userOid: "user-1",
        userKind: "user",
      });
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      expect(res.statusCode).toBe(502);
      expect(res.json()).toEqual({
        code: "upstream_error",
        message: "delegated resolution not configured",
      });
      expect(vendor.tokenCalls()).toEqual([]);
    } finally {
      await app.close();
    }
  });

  it("a provider instruction without a caller kind cannot verify (the schema refuses it)", async () => {
    if (!ok) return;
    const provider = await makeProvider();
    const app = makeApp(cacheFor(provider));
    try {
      // Mint OUTSIDE the strict payload — the shape an edge that never learned
      // the kind would send. The verify fails closed: 401, and the resolution
      // (and the vendor) is never reached.
      const requestId = randomUUID();
      const instruction = await new SignJWT({
        appId: "app-1",
        userOid: "user-1",
        capability: "fetch",
        origin: vendor.issuer,
        requestId,
        env: "prod",
        provider: provider.ref,
      })
        .setProtectedHeader({ alg: "HS256", typ: INSTRUCTION_JWT_TYP })
        .setJti(requestId)
        .setAudience(INSTRUCTION_AUDIENCE)
        .setIssuedAt()
        .setExpirationTime("30s")
        .sign(key);
      const res = await proxyCall(app, instruction, `${vendor.issuer}/api/echo`);
      expect(res.statusCode).toBe(401);
      expect(vendor.tokenCalls()).toEqual([]);
    } finally {
      await app.close();
    }
  });
});
