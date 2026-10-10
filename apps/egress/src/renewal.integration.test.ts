import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { Pool } from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import {
  ConnectionProviderSchema,
  type ConnectionProvider,
  ConnectionMaterialSchema,
  type Env,
  type UserConnection,
} from "@azx-pbc/shared";
import { INSTR_EGRESS_RENEWALS, SPAN_EGRESS_RENEWAL } from "@azx-pbc/shared/telemetry";
import {
  startDevOAuthVendor,
  requestAuthorizationCode,
  exchangeAuthorizationCode,
  newCodeVerifier,
  s256CodeChallenge,
  refreshAccessToken,
  type RunningDevOAuthVendor,
} from "@azx-pbc/dev-oauth-vendor";
import { createSecretStore, type SecretStore } from "@azx-pbc/secret-store";
import {
  ConnectionRenewer,
  renewalLockKey,
  userConnectionFromPg,
  type RenewalTarget,
} from "./renewal.js";
import { createEgressPool } from "./pool.js";
import { makePinnedDispatcher } from "./ssrf.js";
import { EGRESS_SPAN_ATTRS } from "./spanAttributes.js";

/**
 * The renewal operation (ADR-0031 decision 15) against the REAL test database
 * (the `helix_egress` grants and the RLS policies of the
 * connection-substrate migration) and the REAL fixture vendor.
 *
 * The center of gravity is the cross-instance invariant: concurrent
 * renewals driven across independently constructed renewers — each with its own
 * pool, its own custody store, its own pinned transport: two instances of the
 * mechanism plane by every observable measure — against ONE database and ONE
 * fixture vendor must produce exactly one vendor renewal. The fixture's call
 * log is the evidence: the refresh token was presented once.
 *
 * Seeding runs as the table owner (the portal's job); the renewer runs under
 * `helix_egress`. Skips when the role isn't provisioned (CI without db-init) —
 * the other integration suites' fail-soft stance.
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

const VENDOR_TIMEOUT_MS = 1_000;
const REDIRECT_URI = "https://auth.local.helix.azxlabs.io/connections/callback";
const CLIENT_ID = "renewal-fixture-client";
const CLIENT_SECRET = "renewal-fixture-secret-51ab";

let vendor: RunningDevOAuthVendor;
const kek = Buffer.from("renewal-test-kek-0123456789abcdef", "utf8");
const credentialStore: SecretStore = createSecretStore({ devMasterKey: kek });

beforeAll(async () => {
  vendor = await startDevOAuthVendor({
    accessTokenTtlSeconds: 900,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  });
});

const seededIds: string[] = [];

afterAll(async () => {
  await vendor.close();
  await recording.restore();
  if (seededIds.length > 0) {
    const owner = new Pool({ connectionString: OWNER_URL, max: 1 });
    try {
      await owner.query(`DELETE FROM user_connections WHERE id = ANY($1::uuid[])`, [seededIds]);
    } finally {
      await owner.end();
    }
  }
});

/** Per-test teardown: telemetry, vendor modes, and the call log back to baseline. */
afterEach(() => {
  // The adversarial scan (ADR-0037 decision 6, the spanAttributes suite's
  // extension to this operation): EVERY attribute of EVERY span recorded by
  // these tests is allowlisted, no egress span records an exception, and the
  // material this suite moves appears nowhere — the plant scans run on the
  // dummy tokens several tests put in rows and responses.
  for (const span of recording.spans()) {
    for (const key of Object.keys(span.attributes)) {
      expect(EGRESS_SPAN_ATTRS, `${span.name} carried ${key}`).toContain(key);
    }
    expect(span.events.filter((e) => e.name === "exception")).toEqual([]);
    expect(JSON.stringify(span.attributes)).not.toMatch(
      /not-a-vendor-token|winner-(access|refresh)/,
    );
  }
  recording.reset();
  vendor.setModes({ tokenMode: "rotating", authorizeMode: "approve" });
  vendor.resetTokenCalls();
});

async function makeProvider(
  overrides: Partial<ConnectionProvider> = {},
): Promise<ConnectionProvider> {
  return ConnectionProviderSchema.parse({
    id: randomUUID(),
    ref: "renewal-fixture",
    kind: "rest-delegated",
    displayName: "Renewal Fixture",
    authorizeEndpoint: `${vendor.issuer}/authorize`,
    tokenEndpoint: `${vendor.issuer}/token`,
    requestedScopes: [],
    apiOrigins: ["https://api.fixture.test"],
    tokenPlacement: { kind: "header-bearer" },
    env: "prod",
    // Sealed through the SAME custody the renewer opens them with — the
    // provider row holds sealed material, like every real row.
    clientIdMaterial: await credentialStore.seal(CLIENT_ID),
    clientSecretMaterial: await credentialStore.seal(CLIENT_SECRET),
    revision: 1,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  });
}

/**
 * A provider cache fake serving ONE row — the in-memory half of an "instance".
 * Real instances read the same DB through their own LISTEN-driven cache; a
 * shared row object across two fakes is exactly what those caches would both
 * hold.
 */
function cacheOf(row: ConnectionProvider) {
  return {
    get: (id: string) => (id === row.id ? row : undefined),
    getByRef: () => row,
    isLoaded: () => true,
  };
}

/** One independently constructed renewer — one instance of the mechanism plane. */
interface Renewer {
  renewer: ConnectionRenewer;
  pool: Pool;
  delegated: SecretStore;
}

function makeRenewer(
  provider: ConnectionProvider,
  opts: { lockAcquireTimeoutMs?: number } = {},
): Renewer {
  const pool = createEgressPool(egressUrl(), { max: 4 });
  const delegated = createSecretStore({ devMasterKey: kek });
  return {
    renewer: new ConnectionRenewer({
      pool,
      providers: cacheOf(provider),
      credentialStore,
      delegatedStore: delegated,
      dispatcher: makePinnedDispatcher(true, VENDOR_TIMEOUT_MS, []),
      timeoutMs: VENDOR_TIMEOUT_MS,
      allowInsecureConnection: true,
      lockAcquireTimeoutMs: opts.lockAcquireTimeoutMs,
    }),
    pool,
    delegated,
  };
}

/** Drive the fixture's real code flow once; the refresh token it mints is real. */
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

/** Seed one live connection row (as the owner), material sealed under the KEK. */
async function seedConnection(opts: {
  providerId: string;
  userOid?: string;
  env?: Env;
  /** Access-token expiry relative to now; negative = expired (the default). */
  expiresInSec?: number;
  renewBeforeNext?: boolean;
  status?: "live" | "reconnect-needed" | "invalidated";
  tokens: { access: string; refresh: string };
  grantedScopes?: string[];
}): Promise<UserConnection> {
  const delegated = createSecretStore({ devMasterKey: kek });
  const material = JSON.stringify(
    ConnectionMaterialSchema.parse({
      access: await delegated.seal(opts.tokens.access),
      refresh: await delegated.seal(opts.tokens.refresh),
    }),
  );
  const id = randomUUID();
  const userOid = opts.userOid ?? `user-${randomUUID()}`;
  const env = opts.env ?? "prod";
  const expiresInSec = opts.expiresInSec ?? -60;
  const status = opts.status ?? "live";
  await ownerQuery(
    `INSERT INTO user_connections (id, "userOid", "providerId", "providerRevision", env, status,
        material, "grantedScopes", "grantedAt", "expiresAt", "renewBeforeNext", "pendingRetire",
        "lastRenewedAt", "createdAt", "updatedAt")
      VALUES ($1::uuid, $2, $3::uuid, 1, $4, $5, $6, $7::jsonb, now(),
              now() + ($8 || ' seconds')::interval, $9, NULL, NULL, now(), now())`,
    [
      id,
      userOid,
      opts.providerId,
      env,
      status,
      material,
      JSON.stringify(opts.grantedScopes ?? []),
      String(expiresInSec),
      opts.renewBeforeNext ?? false,
    ],
  );
  seededIds.push(id);
  return {
    id,
    userOid,
    providerId: opts.providerId,
    providerRevision: 1,
    env,
    status,
    material,
    grantedScopes: opts.grantedScopes ?? [],
    grantedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + expiresInSec * 1000).toISOString(),
    renewBeforeNext: opts.renewBeforeNext ?? false,
    pendingRetire: null,
    lastRenewedAt: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

/** Read the row back through the egress identity — what the renewer sees. */
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

/** The fixture's refresh-token presentations so far. */
function refreshPresentations(): number {
  return vendor.tokenCalls().filter((c) => c.grantType === "refresh_token").length;
}

/**
 * The advisory locks held on ONE renewal target's key. `pg_locks` spans every
 * session in the database, and the integration suites share one database while
 * vitest runs files in parallel — a concurrent suite's renewal (retire drives
 * real renewals) would fail an unscoped count. The invariant under test is the
 * renewer's own release, which is exactly the per-target key.
 */
async function advisoryLocks(target: RenewalTarget): Promise<number> {
  // The single-bigint lock key is split across pg_locks as classid (high 32
  // bits) and objid (low 32), each displayed as an unsigned oid.
  const key = BigInt(renewalLockKey(target));
  const rows = await ownerQuery<{ count: string }>(
    `SELECT count(*) AS count FROM pg_locks
      WHERE locktype = 'advisory' AND classid::text = $1 AND objid::text = $2`,
    [((key >> 32n) & 0xffffffffn).toString(), (key & 0xffffffffn).toString()],
  );
  return Number(rows[0]?.count ?? "0");
}

/** A raw token endpoint with a scripted response — vendor shapes the fixture's modes cannot express. */
function scriptedTokenServer(
  script: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ origin: string; close: () => Promise<void> }> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => script(req, res));
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

const jsonToken = (body: Record<string, unknown>, status = 200) =>
  scriptedTokenServer((_req, res) => {
    res.statusCode = status;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(body));
  });

describe("renewal — the happy path, both rotation modes", () => {
  it("rotating: stores the replacement, ledger-marks the old material in the same update", async () => {
    if (!ok) return; // role not provisioned — skip
    const provider = await makeProvider();
    const a = makeRenewer(provider);
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: await driveGrant(vendor, "email profile"),
        grantedScopes: ["email", "profile"],
      });
      const before = await readRow(seeded.userOid, provider.id, "prod");

      const result = await a.renewer.renew({
        userOid: seeded.userOid,
        providerId: provider.id,
        env: "prod",
      });

      expect(result.outcome).toBe("refreshed");
      expect(result.accessToken).toMatch(/^[A-Za-z0-9_-]{43}$/);

      const after = await readRow(seeded.userOid, provider.id, "prod");
      expect(after?.status).toBe("live");
      expect(after?.material).not.toBe(before?.material);
      expect(after?.lastRenewedAt).not.toBeNull();
      expect(Date.parse(after?.expiresAt ?? "")).toBeGreaterThan(Date.now() + 800_000);
      // The replacement refresh token was stored; the ledger-marked entry is
      // the ENTIRE old material envelope (the sweep parses and destroys it).
      const fresh = ConnectionMaterialSchema.parse(JSON.parse(after?.material ?? "{}"));
      expect(fresh.refresh).not.toBe(
        ConnectionMaterialSchema.parse(JSON.parse(before?.material ?? "{}")).refresh,
      );
      expect(after?.pendingRetire).toBe(before?.material);
      // The opened access token is the one the result carries — usable material.
      expect(await a.delegated.open(fresh.access)).toBe(result.accessToken);

      // The vendor rotated for real: the old refresh token is dead there, and
      // the new one still works — the grant was not killed by double use.
      expect(refreshPresentations()).toBe(1);
      const oldToken = await a.delegated.open(
        ConnectionMaterialSchema.parse(JSON.parse(before?.material ?? "{}")).refresh,
      );
      const replayed = await refreshAccessToken(vendor, oldToken, {
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
      });
      expect(replayed.ok).toBe(false);
      const freshToken = await a.delegated.open(fresh.refresh);
      const continues = await refreshAccessToken(vendor, freshToken, {
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
      });
      expect(continues.ok).toBe(true);
    } finally {
      await a.pool.end();
    }
  });

  it("non-rotating: retains the existing refresh token and writes no ledger entry", async () => {
    if (!ok) return; // role not provisioned — skip
    vendor.setModes({ tokenMode: "non-rotating" });
    const provider = await makeProvider();
    const a = makeRenewer(provider);
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: await driveGrant(vendor, "email profile"),
        grantedScopes: ["email", "profile"],
      });
      const before = await readRow(seeded.userOid, provider.id, "prod");

      const result = await a.renewer.renew({
        userOid: seeded.userOid,
        providerId: provider.id,
        env: "prod",
      });

      expect(result.outcome).toBe("refreshed");
      const after = await readRow(seeded.userOid, provider.id, "prod");
      expect(after?.status).toBe("live");
      // The access material swapped; the refresh material reference is retained.
      const fresh = ConnectionMaterialSchema.parse(JSON.parse(after?.material ?? "{}"));
      const old = ConnectionMaterialSchema.parse(JSON.parse(before?.material ?? "{}"));
      expect(fresh.access).not.toBe(old.access);
      expect(fresh.refresh).toBe(old.refresh);
      // No ledger entry appears — the retained token is still in use.
      expect(after?.pendingRetire).toBeNull();
      expect(refreshPresentations()).toBe(1);
    } finally {
      await a.pool.end();
    }
  });
});

describe("renewal — cross-instance single-flight", () => {
  it("three independently constructed renewers, one vendor: exactly one refresh presentation", async () => {
    if (!ok) return; // role not provisioned — skip
    const provider = await makeProvider();
    const instances = [makeRenewer(provider), makeRenewer(provider), makeRenewer(provider)];
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: await driveGrant(vendor, "email profile"),
        grantedScopes: ["email", "profile"],
      });

      const results = await Promise.all(
        instances.map((i) =>
          i.renewer.renew({ userOid: seeded.userOid, providerId: provider.id, env: "prod" }),
        ),
      );

      // The vendor's token endpoint observed the refresh token ONCE.
      expect(refreshPresentations()).toBe(1);

      // Losers proceed on the winner's fresh token (or fail temporarily —
      // here the winner's wait is milliseconds, so all three proceed), and
      // every `refreshed` answer carries the same usable material.
      for (const result of results) expect(result.outcome).toBe("refreshed");
      const tokens = new Set(results.map((r) => r.accessToken));
      expect(tokens.size).toBe(1);

      // The grant survived: the committed replacement still works at the vendor.
      const row = await readRow(seeded.userOid, provider.id, "prod");
      const fresh = ConnectionMaterialSchema.parse(JSON.parse(row?.material ?? "{}"));
      const continues = await refreshAccessToken(
        vendor,
        await instances[0]!.delegated.open(fresh.refresh),
        { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
      );
      expect(continues.ok).toBe(true);
    } finally {
      await Promise.all(instances.map((i) => i.pool.end()));
    }
  });

  it("coalesces same-key callers within one instance (the map beneath the lock)", async () => {
    if (!ok) return; // role not provisioned — skip
    const provider = await makeProvider();
    const a = makeRenewer(provider);
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: await driveGrant(vendor, "email"),
        grantedScopes: ["email"],
      });
      const target = { userOid: seeded.userOid, providerId: provider.id, env: "prod" as Env };
      const results = await Promise.all([1, 2, 3, 4, 5].map(() => a.renewer.renew(target)));
      expect(refreshPresentations()).toBe(1);
      for (const result of results) expect(result.outcome).toBe("refreshed");
      expect(new Set(results.map((r) => r.accessToken)).size).toBe(1);
    } finally {
      await a.pool.end();
    }
  });
});

describe("renewal — distinct keys do not share results", () => {
  it("concurrent renewals on distinct users/providers run in parallel, not serialized", async () => {
    if (!ok) return; // role not provisioned — skip
    // Two vendors so the hang provably holds one key's lock while the other
    // key proceeds: if the lock were not keyed per (user, provider, env), the
    // fast renewal could not finish until the hanging one timed out.
    const fastProvider = await makeProvider({ ref: "renewal-fast" });
    const hangVendor = await startDevOAuthVendor({
      accessTokenTtlSeconds: 900,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });
    const hangProvider = await makeProvider({
      ref: "renewal-hang",
      authorizeEndpoint: `${hangVendor.issuer}/authorize`,
      tokenEndpoint: `${hangVendor.issuer}/token`,
    });
    const a = makeRenewer(fastProvider);
    const h = makeRenewer(hangProvider);
    try {
      const fastSeeded = await seedConnection({
        providerId: fastProvider.id,
        tokens: await driveGrant(vendor, "email"),
        grantedScopes: ["email"],
      });
      // Seed the hang connection while ITS vendor still answers, then hang it.
      hangVendor.setModes({ tokenMode: "non-rotating" });
      const hangSeeded = await seedConnection({
        providerId: hangProvider.id,
        userOid: `user-${randomUUID()}`,
        tokens: await driveGrant(hangVendor, "email"),
        grantedScopes: ["email"],
      });
      expect(
        renewalLockKey({ userOid: fastSeeded.userOid, providerId: fastProvider.id, env: "prod" }),
      ).not.toBe(
        renewalLockKey({ userOid: hangSeeded.userOid, providerId: hangProvider.id, env: "prod" }),
      );

      hangVendor.setModes({ tokenMode: "hang" });
      const t0 = Date.now();
      let fastDoneAt = Number.POSITIVE_INFINITY;
      const fastPromise = a.renewer
        .renew({ userOid: fastSeeded.userOid, providerId: fastProvider.id, env: "prod" })
        .then((r) => {
          fastDoneAt = Date.now() - t0;
          return r;
        });
      const hangPromise = h.renewer.renew({
        userOid: hangSeeded.userOid,
        providerId: hangProvider.id,
        env: "prod",
      });

      const [fast, hung] = await Promise.all([fastPromise, hangPromise]);
      expect(fast.outcome).toBe("refreshed");
      expect(hung.outcome).toBe("temporary_failure");
      // The fast renewal did not wait out the hang (its ~1s vendor timeout).
      expect(fastDoneAt).toBeLessThan(700);
      // Each key's vendor call happened once — no cross-key interference.
      expect(vendor.tokenCalls().filter((c) => c.grantType === "refresh_token")).toHaveLength(1);
      expect(hangVendor.tokenCalls().filter((c) => c.grantType === "refresh_token")).toHaveLength(
        1,
      );
      // The hung renewal left its row untouched.
      const hangRow = await readRow(hangSeeded.userOid, hangProvider.id, "prod");
      expect(hangRow?.material).toBe(hangSeeded.material);
    } finally {
      await a.pool.end();
      await h.pool.end();
      await hangVendor.close();
    }
  });
});

describe("renewal — the failure taxonomy", () => {
  it("uncertain rotation: reconnect-needed, and the old token is never re-presented", async () => {
    if (!ok) return; // role not provisioned — skip
    const provider = await makeProvider();
    const a = makeRenewer(provider);
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: await driveGrant(vendor, "email"),
        grantedScopes: ["email"],
      });
      const before = await readRow(seeded.userOid, provider.id, "prod");
      vendor.setModes({ tokenMode: "consumed-then-drop" });

      const first = await a.renewer.renew({
        userOid: seeded.userOid,
        providerId: provider.id,
        env: "prod",
      });
      expect(first.outcome).toBe("uncertain_rotation");
      // The row moved to reconnect-needed; the abandoned material is
      // ledger-marked in the same UPDATE; nothing usable was stored.
      const after = await readRow(seeded.userOid, provider.id, "prod");
      expect(after?.status).toBe("reconnect-needed");
      expect(after?.material).toBe(before?.material);
      expect(after?.pendingRetire).toBe(before?.material);
      expect(after?.lastRenewedAt).toBeNull();
      expect(refreshPresentations()).toBe(1);

      // A second attempt NEVER re-presents the old refresh token: the row is
      // dead for use and the operation refuses before any vendor call.
      const second = await a.renewer.renew({
        userOid: seeded.userOid,
        providerId: provider.id,
        env: "prod",
      });
      expect(second.outcome).toBe("reconnect_required");
      expect(refreshPresentations()).toBe(1);
    } finally {
      await a.pool.end();
    }
  });

  it("temporary failure (hang): the row is untouched, no retry within the attempt", async () => {
    if (!ok) return; // role not provisioned — skip
    const provider = await makeProvider();
    const a = makeRenewer(provider);
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: await driveGrant(vendor, "email"),
        grantedScopes: ["email"],
      });
      const before = await readRow(seeded.userOid, provider.id, "prod");
      vendor.setModes({ tokenMode: "hang" });

      const result = await a.renewer.renew({
        userOid: seeded.userOid,
        providerId: provider.id,
        env: "prod",
      });
      expect(result.outcome).toBe("temporary_failure");
      expect(result.accessToken).toBeUndefined();

      const after = await readRow(seeded.userOid, provider.id, "prod");
      expect(after?.material).toBe(before?.material);
      expect(after?.status).toBe("live");
      expect(after?.pendingRetire).toBeNull();
      expect(after?.lastRenewedAt).toBeNull();
      // One presentation, no vendor retry inside the attempt.
      expect(refreshPresentations()).toBe(1);

      // A later attempt may try again — recovery is the vendor's, not ours.
      vendor.setModes({ tokenMode: "rotating" });
      const retry = await a.renewer.renew({
        userOid: seeded.userOid,
        providerId: provider.id,
        env: "prod",
      });
      expect(retry.outcome).toBe("refreshed");
      expect(refreshPresentations()).toBe(2);
    } finally {
      await a.pool.end();
    }
  });

  it("temporary failure (5xx): classified temporary, row preserved", async () => {
    if (!ok) return; // role not provisioned — skip
    const server = await jsonToken({ error: "server_error", error_description: "overloaded" }, 500);
    const provider = await makeProvider({ tokenEndpoint: `${server.origin}/token` });
    const a = makeRenewer(provider);
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: { access: "access-not-a-vendor-token", refresh: "refresh-not-a-vendor-token" },
        grantedScopes: ["email"],
      });
      const before = await readRow(seeded.userOid, provider.id, "prod");
      const result = await a.renewer.renew({
        userOid: seeded.userOid,
        providerId: provider.id,
        env: "prod",
      });
      expect(result.outcome).toBe("temporary_failure");
      const after = await readRow(seeded.userOid, provider.id, "prod");
      expect(after?.material).toBe(before?.material);
      expect(after?.status).toBe("live");
    } finally {
      await a.pool.end();
      await server.close();
    }
  });

  it("explicit permission loss: reconnect_required and the row moves to reconnect-needed", async () => {
    if (!ok) return; // role not provisioned — skip
    // The vendor granted fewer permissions than the provider requires — the
    // scope field names its set explicitly, so the loss is explicit.
    const server = await jsonToken({
      access_token: "a".repeat(43),
      token_type: "Bearer",
      expires_in: 900,
      scope: "email",
      refresh_token: "r".repeat(43),
    });
    const provider = await makeProvider({
      requestedScopes: ["email", "profile"],
      tokenEndpoint: `${server.origin}/token`,
    });
    const a = makeRenewer(provider);
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: { access: "access-not-a-vendor-token", refresh: "refresh-not-a-vendor-token" },
        grantedScopes: ["email", "profile"],
      });
      const before = await readRow(seeded.userOid, provider.id, "prod");
      const result = await a.renewer.renew({
        userOid: seeded.userOid,
        providerId: provider.id,
        env: "prod",
      });
      expect(result.outcome).toBe("reconnect_required");
      const after = await readRow(seeded.userOid, provider.id, "prod");
      expect(after?.status).toBe("reconnect-needed");
      expect(after?.pendingRetire).toBe(before?.material);
    } finally {
      await a.pool.end();
      await server.close();
    }
  });

  it("malformed client credentials classify admin_action and leave the row alone", async () => {
    if (!ok) return; // role not provisioned — skip
    const server = await jsonToken({ error: "invalid_client" }, 401);
    const provider = await makeProvider({ tokenEndpoint: `${server.origin}/token` });
    const a = makeRenewer(provider);
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: { access: "access-not-a-vendor-token", refresh: "refresh-not-a-vendor-token" },
        grantedScopes: ["email"],
      });
      const before = await readRow(seeded.userOid, provider.id, "prod");
      const result = await a.renewer.renew({
        userOid: seeded.userOid,
        providerId: provider.id,
        env: "prod",
      });
      expect(result.outcome).toBe("admin_action");
      // The connection is not the problem — the provider is. The row stands.
      const after = await readRow(seeded.userOid, provider.id, "prod");
      expect(after?.material).toBe(before?.material);
      expect(after?.status).toBe("live");
    } finally {
      await a.pool.end();
      await server.close();
    }
  });

  it("a missing usable lifetime classifies admin_action", async () => {
    if (!ok) return; // role not provisioned — skip
    const server = await jsonToken({ access_token: "a".repeat(43), token_type: "Bearer" });
    const provider = await makeProvider({ tokenEndpoint: `${server.origin}/token` });
    const a = makeRenewer(provider);
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: { access: "access-not-a-vendor-token", refresh: "refresh-not-a-vendor-token" },
        grantedScopes: ["email"],
      });
      const result = await a.renewer.renew({
        userOid: seeded.userOid,
        providerId: provider.id,
        env: "prod",
      });
      expect(result.outcome).toBe("admin_action");
    } finally {
      await a.pool.end();
      await server.close();
    }
  });
});

describe("renewal — the advisory lock", () => {
  it("a holder of the EXPORTED lock key bounded-blocks a renewal into temporary failure", async () => {
    if (!ok) return; // role not provisioned — skip
    const provider = await makeProvider();
    const a = makeRenewer(provider, { lockAcquireTimeoutMs: 400 });
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: await driveGrant(vendor, "email"),
        grantedScopes: ["email"],
      });
      const target = { userOid: seeded.userOid, providerId: provider.id, env: "prod" as Env };
      // A foreign holder (the test's own session) proves the key composition is
      // load-bearing: the renewer blocks on exactly the key it exports.
      const holder = new Pool({ connectionString: egressUrl(), max: 1 });
      try {
        await holder.query(`SELECT pg_advisory_lock($1::bigint)`, [renewalLockKey(target)]);
        const t0 = Date.now();
        const result = await a.renewer.renew(target);
        expect(Date.now() - t0).toBeGreaterThanOrEqual(350);
        expect(result.outcome).toBe("temporary_failure");
        expect(refreshPresentations()).toBe(0);
      } finally {
        await holder.query(`SELECT pg_advisory_unlock($1::bigint)`, [renewalLockKey(target)]);
        await holder.end();
      }
      // With the holder gone, the same key acquires and renews.
      const result = await a.renewer.renew(target);
      expect(result.outcome).toBe("refreshed");
    } finally {
      await a.pool.end();
    }
  });

  it("releases the lock and the client on every exit path", async () => {
    if (!ok) return; // role not provisioned — skip
    const provider = await makeProvider();
    const a = makeRenewer(provider, { lockAcquireTimeoutMs: 500 });
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: await driveGrant(vendor, "email"),
        grantedScopes: ["email"],
      });
      const target = { userOid: seeded.userOid, providerId: provider.id, env: "prod" as Env };
      /** Re-expire the row between exit paths (a refreshed row short-circuits). */
      const reexpire = (): Promise<void> =>
        ownerQuery(
          `UPDATE user_connections SET "expiresAt" = now() - interval '60 seconds' WHERE id = $1`,
          [seeded.id],
        ).then(() => {});

      // Every outcome below releases: a warm cycle + one of each exit path.
      expect(await a.renewer.renew(target)).toMatchObject({ outcome: "refreshed" });
      expect(await advisoryLocks(target)).toBe(0);

      // temporary_failure (the vendor hangs).
      await reexpire();
      vendor.setModes({ tokenMode: "hang" });
      expect(await a.renewer.renew(target)).toMatchObject({ outcome: "temporary_failure" });
      expect(await advisoryLocks(target)).toBe(0);

      // uncertain_rotation (consumed-then-drop).
      await reexpire();
      vendor.setModes({ tokenMode: "consumed-then-drop" });
      expect(await a.renewer.renew(target)).toMatchObject({ outcome: "uncertain_rotation" });
      expect(await advisoryLocks(target)).toBe(0);

      // reconnect_required (a dead row — no lock is even taken).
      expect(await a.renewer.renew(target)).toMatchObject({ outcome: "reconnect_required" });
      expect(await advisoryLocks(target)).toBe(0);

      // Repeated cycles return the pool to its baseline — no leaked clients,
      // nothing stuck waiting on checkout, no advisory lock left behind.
      vendor.setModes({ tokenMode: "rotating" });
      const reconnect = await readRow(seeded.userOid, provider.id, "prod");
      expect(reconnect?.status).toBe("reconnect-needed");
      for (let cycle = 0; cycle < 3; cycle += 1) {
        const fresh = makeRenewer(provider);
        const row = await seedConnection({
          providerId: provider.id,
          tokens: await driveGrant(vendor, "email"),
          grantedScopes: ["email"],
        });
        await fresh.renewer.renew({ userOid: row.userOid, providerId: provider.id, env: "prod" });
        const cycleTarget = {
          userOid: row.userOid,
          providerId: provider.id,
          env: "prod" as Env,
        };
        expect(await advisoryLocks(cycleTarget)).toBe(0);
        expect(fresh.pool.totalCount).toBeLessThanOrEqual(2);
        expect(fresh.pool.waitingCount).toBe(0);
        await fresh.pool.end();
      }
    } finally {
      await a.pool.end();
    }
  });

  it("a CAS loss retires the freshly-sealed material and proceeds on the row that won", async () => {
    if (!ok) return; // role not provisioned — skip
    // The scripted endpoint swaps the row (a reconnect upsert winning) WHILE
    // the renewal's vendor call is in flight — then answers with fresh
    // tokens. The CAS compares the stale material and must lose.
    let winnerEnvelope = "";
    let swapped = false;
    const server = await scriptedTokenServer((_req, res) => {
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
      if (swapped) return respond();
      swapped = true;
      void ownerQuery(
        `UPDATE user_connections SET material = $2, "expiresAt" = now() + interval '900 seconds'
          WHERE id = $1`,
        [winnerId, winnerEnvelope],
      ).then(respond);
    });
    const provider = await makeProvider({
      requestedScopes: ["email"],
      tokenEndpoint: `${server.origin}/token`,
    });
    const a = makeRenewer(provider);
    const seeded = await seedConnection({
      providerId: provider.id,
      tokens: { access: "access-not-a-vendor-token", refresh: "refresh-not-a-vendor-token" },
      grantedScopes: ["email"],
    });
    const winnerId = seeded.id;
    const stale = seeded.material;
    winnerEnvelope = JSON.stringify(
      ConnectionMaterialSchema.parse({
        access: await a.delegated.seal("winner-access"),
        refresh: await a.delegated.seal("winner-refresh"),
      }),
    );

    try {
      const result = await a.renewer.renew({
        userOid: seeded.userOid,
        providerId: provider.id,
        env: "prod",
      });
      // The lost race does not clobber the winner: the row keeps the
      // reconnect's material, and the renewal answers per the design —
      // proceed on the row that won (its fresh material is usable).
      expect(result.outcome).toBe("refreshed");
      const after = await readRow(seeded.userOid, provider.id, "prod");
      expect(
        await a.delegated.open(
          ConnectionMaterialSchema.parse(JSON.parse(after?.material ?? "{}")).access,
        ),
      ).toBe("winner-access");

      // The freshly-sealed (orphaned) material was ledger-marked for the
      // sweep's destroy — never a row's current material.
      expect(after?.pendingRetire).not.toBeNull();
      expect(after?.pendingRetire).not.toBe(winnerEnvelope);
      expect(after?.pendingRetire).not.toBe(stale);
      const orphaned = ConnectionMaterialSchema.parse(JSON.parse(after?.pendingRetire ?? "{}"));
      expect(await a.delegated.open(orphaned.refresh)).toBe("r".repeat(43));
    } finally {
      await server.close();
      await a.pool.end();
    }
  });
});

describe("renewal — telemetry (ADR-0037)", () => {
  it("the span carries only allowlisted attributes and the counter counts outcomes", async () => {
    if (!ok) return; // role not provisioned — skip
    const provider = await makeProvider();
    const a = makeRenewer(provider);
    try {
      const seeded = await seedConnection({
        providerId: provider.id,
        tokens: await driveGrant(vendor, "email"),
        grantedScopes: ["email"],
      });
      const result = await a.renewer.renew({
        userOid: seeded.userOid,
        providerId: provider.id,
        env: "prod",
      });
      expect(result.outcome).toBe("refreshed");

      const spans = recording.spans().filter((s) => s.name === SPAN_EGRESS_RENEWAL);
      expect(spans.length).toBeGreaterThanOrEqual(1);
      const span = spans.at(-1)!;
      for (const key of Object.keys(span.attributes)) {
        expect(EGRESS_SPAN_ATTRS, `${key} is not on the egress allowlist`).toContain(key);
      }
      expect(span.attributes["helix.outcome"]).toBe("refreshed");
      expect(span.attributes["helix.env"]).toBe("prod");
      expect(span.attributes["helix.provider_ref"]).toBe("renewal-fixture");
      // No exception events, and none of the moved material in any attribute —
      // the tokens this test knows are planted nowhere on the span.
      expect(span.events.filter((e) => e.name === "exception")).toHaveLength(0);
      const serialized = JSON.stringify(span.attributes);
      expect(serialized).not.toContain(result.accessToken ?? "");

      const metrics = await recording.metrics();
      const renewals = metrics.filter((m) => m.name === INSTR_EGRESS_RENEWALS);
      expect(renewals.length).toBeGreaterThan(0);
      const refreshed = renewals.find(
        (m) =>
          m.attributes["helix.outcome"] === "refreshed" && m.attributes["helix.env"] === "prod",
      );
      expect(refreshed?.value).toBeGreaterThanOrEqual(1);
      for (const point of renewals) {
        for (const key of Object.keys(point.attributes)) {
          expect(["helix.outcome", "helix.env"]).toContain(key);
        }
      }
    } finally {
      await a.pool.end();
    }
  });
});
