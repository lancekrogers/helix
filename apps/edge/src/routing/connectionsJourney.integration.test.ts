import { execSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { connect as tcpConnect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as createTlsServer, type Server as TlsServer } from "node:tls";
import type { AddressInfo } from "node:net";
import { Agent, request as undiciRequest } from "undici";
import { Pool } from "pg";
import type { FastifyInstance } from "fastify";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  CONNECTIONS_CALLBACK_PATH,
  CONSENT_NONCE_ENTRY_PATH,
  ConnectionMaterialSchema,
  DevConsentStartResponseSchema,
  FETCH_ERROR_CODES,
} from "@azx-pbc/shared";
import type { SecretStore } from "@azx-pbc/secret-store";
import { createSecretStore } from "@azx-pbc/secret-store";
import { startDevOAuthVendor, type RunningDevOAuthVendor } from "@azx-pbc/dev-oauth-vendor";
import { buildApp as buildEgressApp } from "@azx-pbc/egress/app";
import { CredentialRetirementSweep } from "@azx-pbc/egress/retire";
import { LiveProviders } from "@azx-pbc/egress/providerListener";
import { buildTestApp, uniqueSlug, type TestApp } from "@azx-pbc/portal/test-harness";
import { createPrismaClient } from "@azx-pbc/portal/db-client";
import { deriveExchangeKey } from "@azx-pbc/portal/internal-jwt";
import { buildApp as buildEdgeApp } from "../app.js";
import { buildDevGateway } from "../devGateway/app.js";
import { PgDevTokenStore } from "../devGateway/devTokenStore.js";
import { deriveInstructionKey } from "../gateway/instruction.js";
import { HttpEgressProvider } from "../gateway/egressProvider.js";
import { PgUsageStore } from "../gateway/usage.js";
import { LiveRegistry } from "../registry/listener.js";
import { PgSessionStore, hashSessionToken, newSessionId } from "../auth/sessions.js";
import { SESSION_COOKIE } from "../auth/cookies.js";
import { HttpPortalProvider } from "../routing/portalProvider.js";
import { FakeBlobReader, FakeOidcClient } from "../test/fakes.js";
import { testAuthConfig, testDevGatewayConfig, testEdgeConfig } from "../test/config.js";

/**
 * The assembled OAuth-connections journey:
 * the REAL edge, portal, egress and dev-gateway apps composed the way
 * production composes them — edge→portal over `HttpPortalProvider`, edge→egress
 * over `HttpEgressProvider`, portal→egress over `PORTAL_EGRESS_URL`, egress→
 * vendor over the pinned transport, the fixture vendor as the one
 * vendor stand-in — every inter-service hop on real HTTP on ephemeral ports.
 * The suite plays the browser the `flow.integration.test.ts` way: `app.inject()`
 * for the edge/dev-gateway front door, real (undici) fetch for the vendor's
 * authorize screen. It never inserts a finished connection to drive a later
 * hop — every row a later leg reads is an earlier leg's output; only apps,
 * providers, and dev tokens are arranged, through the portal's real API.
 *
 * Isolation: the cleanup leg runs a REAL `CredentialRetirementSweep`, which
 * destroys every ledger mark it finds — so the whole suite runs against its
 * own scratch database (the `retire.integration.test.ts` pattern), created
 * from the same migrations and dropped afterwards. The runtime roles
 * (`helix_edge` / `helix_egress` / `helix_dev`) are REQUIRED — every store is
 * constructed on its production role's URL, and an unprovisioned cluster
 * fails the suite loudly instead of skipping — an unprovisioned green run is
 * not evidence.
 *
 * The fixture vendor's authorize URL must be `https://` for the entry points'
 * redirect hygiene to hand it to a browser, so the suite terminates TLS in
 * front of the vendor's plain-HTTP listener (a raw socket pump — test
 * infrastructure at the browser boundary, like the browser stand-in itself;
 * no platform seam is touched, and egress's own vendor calls ride the http
 * issuer the dev seams allow).
 *
 * Watched-fail (the missing-connection bar): with the suite green,
 * the edge's `portalUrl` seam was once pointed at a dead port — unwiring the
 * start route's consult join. The prod-journey test failed at its first
 * assert (the start route answered its 503 couldn't-start page instead of a
 * 302 to the vendor; no connection row appeared and the delegated call 403'd).
 * The seam was restored and the suite re-run green. Each asserted hop is a
 * real production join: consult (edge→portal internal JWT), authorize redirect
 * (edge→vendor URL), callback (edge proxy→portal→egress exchange), CAS save,
 * delegated call (edge→egress→vendor echo), metering (the edge's ledger), and
 * cleanup (the egress sweep).
 */

// ── Test topology ─────────────────────────────────────────────────────────────

const BASE = "local.helix.azxlabs.io";
const AUTH_HOST = `auth.${BASE}`;
const CALLBACK_URL = `https://${AUTH_HOST}:8080${CONNECTIONS_CALLBACK_PATH}`;
const DEV_ORIGIN = "https://dev-app.example.test";
const ADMIN_GROUP = "platform-admin";

/** The scratch database this suite owns (the retire-suite pattern). */
const OWNER_URL = process.env.TEST_DATABASE_URL ?? "postgresql://helix:helix@db:5432/helix_test";
const JOURNEY_DB = "helix_journey_test";
const JOURNEY_URL = OWNER_URL.replace(/\/[^/]+$/, `/${JOURNEY_DB}`);

/** Least-privilege role URLs, derived from the owner URL like the role-split suite. */
function roleUrl(role: string): string {
  const u = new URL(JOURNEY_URL);
  u.username = role;
  u.password = role;
  return u.toString();
}

const INTERNAL_SECRET = Buffer.from(process.env.HELIX_INTERNAL_SECRET ?? "", "utf8");
const EXCHANGE_SECRET = Buffer.from(process.env.HELIX_EXCHANGE_SECRET ?? "", "utf8");
const INSTRUCTION_SECRET = randomBytes(48);
const instructionKey = deriveInstructionKey(INSTRUCTION_SECRET);
const exchangeKey = deriveExchangeKey(EXCHANGE_SECRET);

// Custody: the app-secrets KEK is shared portal↔egress (the portal seals the
// provider's client credentials, egress opens them); the delegated KEK is
// egress-only — the portal never sees it.
const appSecretsKek = randomBytes(32);
const delegatedKek = randomBytes(32);
const portalCustody = createSecretStore({ devMasterKey: appSecretsKek });
const innerDelegated = createSecretStore({ devMasterKey: delegatedKek });

/** The delegated custody with an observable destroy: the dev envelope's own
 * destroy is a no-op by design (the ciphertext lives in the row), so the
 * destroy CALL is the observable "removed from active custody" event — the
 * same trick the retire suite uses. */
const destroyed: string[] = [];
const delegatedCustody: SecretStore = {
  seal: (value) => innerDelegated.seal(value),
  open: (material) => innerDelegated.open(material),
  destroy: async (material) => {
    destroyed.push(material);
    await innerDelegated.destroy(material);
  },
};

let vendor: RunningDevOAuthVendor;
let rotatingVendor: RunningDevOAuthVendor;
let staticVendor: RunningDevOAuthVendor;
let portal: TestApp;
let edge: FastifyInstance;
let devGateway: FastifyInstance;
let egress: FastifyInstance;
let liveRegistry: LiveRegistry;
let providers: LiveProviders;
let sweep: CredentialRetirementSweep | null = null;
let delegatedPool: Pool;
let sessionsStore: PgSessionStore;
const terminators: TlsServer[] = [];
const terminatorSockets: Set<import("node:net").Socket>[] = [];
/** The https front for one vendor's authorize screen. */
function terminatorPortOf(v: RunningDevOAuthVendor): number {
  const port = terminatorPorts.get(v);
  expect(port, "no TLS terminator for this vendor").toBeTruthy();
  return port as number;
}
const terminatorPorts = new Map<RunningDevOAuthVendor, number>();
/** Loopback agent for the suite's browser hops to the TLS terminator. */
const browserAgent = new Agent({ connect: { rejectUnauthorized: false } });

// ── Polling on observable state (no fixed sleeps) ────────────────────────────

async function pollUntil<T>(
  attempt: () => Promise<T | null>,
  label: string,
  ms = 5_000,
): Promise<T> {
  const deadline = Date.now() + ms;
  for (;;) {
    const value = await attempt();
    if (value !== null) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

// ── Fixtures (arrange — everything through real surfaces) ────────────────────

/** The prod principal: session user, app owner, My Connections actor. */
const userOid = `journey-user-${randomUUID().slice(0, 8)}`;

interface Fixture {
  slug: string;
  appId: string;
  ref: string;
  /** The provider row ids, per tier (a ref may exist in both). */
  providerIds: { prod?: string; dev?: string };
  providerRevision: number;
  displayName: string;
  devToken?: string;
}

function providerIdOf(f: Fixture, env: "prod" | "dev"): string {
  const id = f.providerIds[env];
  expect(id, `fixture arranged no ${env} provider row`).toBeTruthy();
  return id as string;
}

async function ownerQuery<T extends Record<string, unknown>>(
  sql: string,
  values: unknown[] = [],
): Promise<T[]> {
  const pool = new Pool({ connectionString: JOURNEY_URL, max: 1 });
  try {
    return (await pool.query<T>(sql, values)).rows;
  } finally {
    await pool.end();
  }
}

async function portalApi(
  method: "GET" | "POST" | "PUT" | "DELETE",
  url: string,
  token: string,
  payload?: Record<string, unknown>,
): Promise<{ statusCode: number; body: Record<string, unknown> }> {
  const res = await portal.app.inject({
    method,
    url,
    headers: { authorization: `Bearer ${token}` },
    ...(payload === undefined ? {} : { payload }),
  });
  return {
    statusCode: res.statusCode,
    body: res.body === "" ? {} : (res.json() as Record<string, unknown>),
  };
}

/** A live version row, so the projection entry looks deployed (arrange-time state). */
async function seedLiveVersion(appId: string): Promise<void> {
  await ownerQuery(
    `INSERT INTO versions (id, "appId", number, "blobPrefix", status, "createdAt")
     VALUES (gen_random_uuid(), $1::uuid, 1, $2, 'live', now())`,
    [appId, `apps/${appId}/1/`],
  );
  await ownerQuery(
    `UPDATE apps SET "currentVersionId" = (SELECT id FROM versions WHERE "appId" = $1::uuid) WHERE id = $1::uuid`,
    [appId],
  );
}

async function waitForRegistry(slug: string): Promise<void> {
  await pollUntil(
    async () => (liveRegistry.getApp(slug) === undefined ? null : true),
    `registry entry for ${slug}`,
  );
}

/**
 * Arrange one journey fixture through the portal's REAL API: the app (+ a live
 * version), the provider row(s) in the requested tiers (client credentials
 * sealed by the portal's own create path into the custody egress opens), the
 * manifest binding, its approval, and — for the dev tier — the owner's dev
 * token. Waits until the edge's LIVE registry projection has picked the app up.
 */
async function seedFixture(
  tag: string,
  opts: {
    envs: Array<"prod" | "dev">;
    vendorToUse: RunningDevOAuthVendor;
    scopes?: string[];
    devToken?: boolean;
  },
): Promise<Fixture> {
  const ref = `j-${tag}-${randomUUID().replace(/-/g, "").slice(0, 10)}`;
  const slug = uniqueSlug("journey");
  const displayName = "Journey Vendor";

  const created = await portalApi("POST", "/api/v1/apps", "owner", {
    slug,
    displayName: "Journey app",
    visibility: { mode: "internal" },
  });
  expect(created.statusCode).toBe(201);
  const appId = (created.body as { id: string }).id;
  await seedLiveVersion(appId);

  // The provider row(s) — created through the portal's real route, so the
  // client credentials cross the boundary in plaintext exactly once and land
  // sealed in the custody egress opens.
  const providerIds: { prod?: string; dev?: string } = {};
  let providerRevision = 0;
  for (const env of opts.envs) {
    const made = await portalApi("POST", "/api/v1/providers", "admin", {
      ref,
      kind: "rest-delegated",
      displayName,
      // The authorize endpoint is the TLS-terminated front for the fixture's
      // authorize screen (https is the entry points' redirect-hygiene bar);
      // every egress-owned vendor call rides the fixture's http issuer.
      authorizeEndpoint: `https://localhost:${terminatorPortOf(opts.vendorToUse)}/authorize`,
      tokenEndpoint: `${opts.vendorToUse.issuer}/token`,
      requestedScopes: opts.scopes ?? ["read", "write"],
      apiOrigins: [opts.vendorToUse.issuer],
      tokenPlacement: { kind: "header-bearer" },
      env,
      clientId: "journey-fixture-client",
      clientSecret: "journey-fixture-client-secret-5f3a",
    });
    expect(made.statusCode).toBe(201);
    providerIds[env] = made.body.id as string;
    providerRevision = made.body.revision as number;
  }

  // TEMP-DEBUG: time the cache wait
  {
    const t0 = Date.now();
    await pollUntil(
      async () =>
        opts.envs.every((env) => providers.get(providerIds[env]!)?.revision === providerRevision)
          ? true
          : null,
      "egress's provider cache catching up to the seeded providers",
      15_000,
    );
    console.log(`TEMP-DEBUG cache wait took ${Date.now() - t0}ms`);
  }

  // The manifest binding + its approval — the provider-stamped filing the
  // consult later re-checks.
  const put = await portalApi("PUT", `/api/v1/apps/${slug}/manifest`, "owner", {
    capabilities: {
      mcp: [],
      externalOrigins: [],
      fetch: {
        shim: false,
        origins: [{ origin: opts.vendorToUse.issuer, provider: ref }],
      },
    },
  });
  expect(put.statusCode).toBe(200);
  const approved = await portalApi(
    "POST",
    `/api/v1/approvals/${put.body.pending as string}/approve`,
    "admin",
  );
  expect(approved.statusCode).toBe(200);

  let devToken: string | undefined;
  if (opts.devToken) {
    const minted = await portalApi("POST", `/api/v1/apps/${slug}/dev-tokens`, "owner", {
      origins: [DEV_ORIGIN],
    });
    expect(minted.statusCode).toBe(201);
    devToken = minted.body.token as string;
  }

  await waitForRegistry(slug);

  // The journeys consume two projections, both NOTIFY-driven with reconcile
  // cadences (the edge's registry, egress's provider cache), and both can lose
  // a just-seeded race on a slow runner: the delegated call then answers the
  // EDGE's allowlist 403 ("not a proxied origin"), or the exchange answers
  // provider_unavailable (the failed-provider page) — for a fixture the very
  // next moment serves fine. Wait for each projection to hold what the
  // journeys will actually consume; 15s, not the 5s poll default, because the
  // caches' own reconcile intervals (5s egress / 60s edge) outlast it.
  await pollUntil(
    async () =>
      opts.envs.every((env) => providers.get(providerIds[env]!)?.revision === providerRevision)
        ? true
        : null,
    "egress's provider cache catching up to the seeded providers",
    15_000,
  );
  await pollUntil(
    async () =>
      liveRegistry.getApp(slug)?.fetch.connections.has(opts.vendorToUse.issuer) === true
        ? true
        : null,
    "the edge's registry projection carrying the bound fetch origin",
    15_000,
  );
  return {
    slug,
    appId,
    ref,
    providerIds,
    providerRevision,
    displayName,
    devToken,
  };
}

/** A real session row for the app user — the real store, on the helix_edge role. */
async function seedSession(appId: string): Promise<string> {
  const token = randomBytes(32).toString("base64url");
  await sessionsStore.createActive(
    {
      id: newSessionId(),
      appId,
      user: {
        oid: userOid,
        displayName: "Alice Anders",
        name: "Alice Anders",
        email: "alice@azx.dev",
        kind: "user",
        groups: [],
      },
      refreshDueAt: new Date(Date.now() + 3_600_000),
      expiresAt: new Date(Date.now() + 8 * 3_600_000),
    },
    hashSessionToken(token),
  );
  return token;
}

// ── The journey's browser half ────────────────────────────────────────────────

const appHostOf = (slug: string): string => `${slug}.${BASE}`;
const appOriginOf = (slug: string): string => `https://${appHostOf(slug)}:8080`;

/** Narrow the dev start response to its popup URL (an outcomeless response is
 * a broken journey — the expect above it has already failed). */
function popupUrlOf(started: ReturnType<typeof DevConsentStartResponseSchema.parse>): string {
  expect(started.outcome).toBe("started");
  if (started.outcome !== "started") throw new Error("the dev consult did not start");
  return started.popupUrl;
}

/**
 * Follow the start route's 302 through the (TLS-terminated) vendor authorize
 * screen; returns the vendor's redirect back to the fixed callback.
 */
async function vendorAuthorize(authorizeUrl: string): Promise<{ code: string; state: string }> {
  const res = await undiciRequest(authorizeUrl, { dispatcher: browserAgent });
  await res.body.dump();
  expect(res.statusCode).toBe(302);
  const location = res.headers.location;
  expect(typeof location).toBe("string");
  const target = new URL(location as string);
  expect(target.origin + target.pathname).toBe(
    `https://${AUTH_HOST}:8080${CONNECTIONS_CALLBACK_PATH}`,
  );
  const code = target.searchParams.get("code");
  const state = target.searchParams.get("state");
  expect(code).toBeTruthy();
  expect(state).toBeTruthy();
  return { code: code as string, state: state as string };
}

/** The prod entry: the app user's explicit start on the app host. */
async function prodStart(
  slug: string,
  ref: string,
  sessionCookie: string,
): Promise<{ status: number; location?: string; body: string }> {
  const res = await edge.inject({
    url: `/_api/connections/${ref}/start`,
    headers: {
      host: appHostOf(slug),
      origin: appOriginOf(slug),
      cookie: `${SESSION_COOKIE}=${sessionCookie}`,
    },
  });
  return {
    status: res.statusCode,
    location: res.headers.location as string | undefined,
    body: res.body,
  };
}

/** The vendor's redirect delivered to the auth host — the edge's reverse proxy
 * forwards it to the real portal. */
async function callbackThroughEdge(
  query: Record<string, string>,
): Promise<{ status: number; body: string }> {
  const res = await edge.inject({
    url: `${CONNECTIONS_CALLBACK_PATH}?${new URLSearchParams(query).toString()}`,
    headers: { host: `${AUTH_HOST}:8080` },
  });
  return { status: res.statusCode, body: res.body };
}

/** Open the popup URL (the nonce entry) through the edge's auth-host proxy. */
async function openPopup(
  popupUrl: string,
): Promise<{ status: number; location?: string; body: string }> {
  const url = new URL(popupUrl);
  const res = await edge.inject({
    url: `${url.pathname}${url.search}`,
    headers: { host: `${AUTH_HOST}:8080` },
  });
  return {
    status: res.statusCode,
    location: res.headers.location as string | undefined,
    body: res.body,
  };
}

/** One delegated call through the edge's real fetch gateway → real egress →
 * the fixture's API destination. */
async function delegatedCall(
  slug: string,
  sessionCookie: string,
  target: string,
): Promise<{ status: number; body: string }> {
  const res = await edge.inject({
    url: `/_api/fetch/${target}`,
    method: "POST",
    headers: {
      host: appHostOf(slug),
      origin: appOriginOf(slug),
      "sec-fetch-site": "same-origin",
      cookie: `${SESSION_COOKIE}=${sessionCookie}`,
      "content-type": "application/json",
    },
    payload: "{}",
  });
  return { status: res.statusCode, body: res.body };
}

/** Same, through the dev gateway (bearer dev token, env=dev). */
async function devDelegatedCall(
  slug: string,
  token: string,
  target: string,
): Promise<{ status: number; body: string }> {
  const res = await devGateway.inject({
    url: `/${slug}/_api/fetch/${target}`,
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      origin: DEV_ORIGIN,
      "content-type": "application/json",
    },
    payload: "{}",
  });
  return { status: res.statusCode, body: res.body };
}

/** Open a connection row's sealed material through the delegated custody. */
async function openMaterial(material: string): Promise<{ access: string; refresh: string }> {
  const envelope = ConnectionMaterialSchema.parse(JSON.parse(material));
  return {
    access: await innerDelegated.open(envelope.access),
    refresh: await innerDelegated.open(envelope.refresh),
  };
}

interface GatewayRow {
  outcome: string;
  userOid: string;
  userKind: string | null;
  userName: string | null;
  userEmail: string | null;
  capability: string;
  model: string;
  path: string | null;
  method: string | null;
  statusCode: number | null;
  [key: string]: unknown;
}

/** The journey's real metered rows — the ledger write is
 * fire-and-forget beside the response, so poll for the outcome. */
async function gatewayRow(appId: string, outcome: string): Promise<GatewayRow> {
  return pollUntil(async () => {
    const rows = await ownerQuery<GatewayRow>(
      `SELECT outcome, "userOid", "userKind", "userName", "userEmail", capability, model,
              path, method, "statusCode"
         FROM gateway_calls WHERE "appId" = $1::uuid AND outcome = $2`,
      [appId, outcome],
    );
    return rows[0] ?? null;
  }, `gateway_calls row with outcome ${outcome}`);
}

/** Connect one app user (or developer) through the FULL prod or dev journey;
 * returns the saved row. The helper exists so the multi-connect legs each
 * drive the real entry points, never a seeded connection. */
async function connectJourney(
  f: Fixture,
  opts: { env: "prod" | "dev"; sessionCookie?: string; devToken?: string },
): Promise<{ status: number; body: string }> {
  if (opts.env === "prod") {
    const start = await prodStart(f.slug, f.ref, opts.sessionCookie as string);
    expect(start.status).toBe(302);
    const redirect = await vendorAuthorize(start.location as string);
    return callbackThroughEdge(redirect);
  }
  const start = await devGateway.inject({
    method: "POST",
    url: `/${f.slug}/_api/connections/${f.ref}/start`,
    headers: { authorization: `Bearer ${opts.devToken as string}`, origin: DEV_ORIGIN },
  });
  expect(start.statusCode).toBe(200);
  const entry = await openPopup(popupUrlOf(DevConsentStartResponseSchema.parse(start.json())));
  expect(entry.status).toBe(302);
  const redirect = await vendorAuthorize(entry.location as string);
  return callbackThroughEdge(redirect);
}

/** The app-facing connection-status read (ADR-0031 as amended): the prod GET
 * on the app host — session cookie, no Origin (a read), like the real app. */
async function statusRead(
  slug: string,
  ref: string,
  sessionCookie: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await edge.inject({
    url: `/_api/connections/${ref}/status`,
    headers: {
      host: appHostOf(slug),
      cookie: `${SESSION_COOKIE}=${sessionCookie}`,
    },
  });
  return {
    status: res.statusCode,
    body: res.body === "" ? {} : (res.json() as Record<string, unknown>),
  };
}

/** The dev-tier status read — the bearer GET through the dev gateway. */
async function devStatusRead(
  slug: string,
  ref: string,
  token: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await devGateway.inject({
    url: `/${slug}/_api/connections/${ref}/status`,
    headers: { authorization: `Bearer ${token}`, origin: DEV_ORIGIN },
  });
  return {
    status: res.statusCode,
    body: res.body === "" ? {} : (res.json() as Record<string, unknown>),
  };
}

// ── Composition ───────────────────────────────────────────────────────────────

beforeAll(async () => {
  // The scratch database, from the same migrations (the role-conditional
  // grants ride along) — dropped in afterAll.
  const adminUrl = OWNER_URL.replace(/\/[^/]+$/, "/helix");
  execSync(`psql "${adminUrl}" -c "DROP DATABASE IF EXISTS ${JOURNEY_DB} WITH (FORCE)"`, {
    stdio: "pipe",
  });
  execSync(`psql "${adminUrl}" -c "CREATE DATABASE ${JOURNEY_DB}"`, { stdio: "pipe" });
  execSync("pnpm --filter @azx-pbc/portal exec prisma migrate deploy", {
    stdio: "pipe",
    env: { ...process.env, DATABASE_URL: JOURNEY_URL },
  });

  // The runtime roles are REQUIRED (an unprovisioned green run is not
  // evidence) — fail loudly rather than skip.
  const missing: string[] = [];
  for (const role of ["helix_edge", "helix_egress", "helix_dev"]) {
    const probe = new Pool({ connectionString: roleUrl(role), max: 1 });
    try {
      await probe.query("SELECT 1");
    } catch {
      missing.push(role);
    } finally {
      await probe.end();
    }
  }
  expect(
    missing,
    `runtime roles not provisioned (${missing.join(", ")}) — run ` +
      `.devcontainer/db-init/01-roles.sql; an unprovisioned run is not evidence`,
  ).toEqual([]);

  // The fixture vendors. The rotation legs need REAL expiry, so their
  // instances carry the one-second TTL knob; the main journey uses the
  // default (long) lifetime.
  vendor = await startDevOAuthVendor({
    clientId: "journey-fixture-client",
    clientSecret: "journey-fixture-client-secret-5f3a",
    redirectUris: [CALLBACK_URL],
  });
  rotatingVendor = await startDevOAuthVendor({
    accessTokenTtlSeconds: 1,
    clientId: "journey-fixture-client",
    clientSecret: "journey-fixture-client-secret-5f3a",
    redirectUris: [CALLBACK_URL],
  });
  staticVendor = await startDevOAuthVendor({
    accessTokenTtlSeconds: 1,
    tokenMode: "non-rotating",
    clientId: "journey-fixture-client",
    clientSecret: "journey-fixture-client-secret-5f3a",
    redirectUris: [CALLBACK_URL],
  });

  // A TLS terminator in front of each vendor's authorize endpoint (a raw
  // socket pump: TLS ends at the terminator, plain http reaches the vendor).
  // One per vendor instance, so a fixture's authorize URL always reaches ITS
  // vendor's token endpoint.
  const certDir = mkdtempSync(join(tmpdir(), "journey-tls-"));
  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 2 -nodes ` +
      `-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"`,
    { cwd: certDir, stdio: "pipe" },
  );
  const tlsOptions = {
    key: readFileSync(join(certDir, "key.pem")),
    cert: readFileSync(join(certDir, "cert.pem")),
  };
  for (const v of [vendor, rotatingVendor, staticVendor]) {
    const sockets = new Set<import("node:net").Socket>();
    const server = createTlsServer(tlsOptions, (client) => {
      sockets.add(client);
      client.on("close", () => sockets.delete(client));
      const upstream = tcpConnect(v.port, "127.0.0.1", () => {
        client.pipe(upstream);
        upstream.pipe(client);
      });
      upstream.on("error", () => client.destroy());
      client.on("error", () => upstream.destroy());
    });
    terminatorSockets.push(sockets);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    terminators.push(server);
    terminatorPorts.set(v, (server.address() as AddressInfo).port);
  }

  // The REAL egress: the delegated wiring on the helix_egress role, the real
  // provider cache (LISTEN/NOTIFY), the real exchange operation sharing the
  // portal's custody — and, below, the retirement sweep on a short cadence
  // (the scheduling seam: the cadence bound is asserted through it, never
  // by waiting wall-clock minutes).
  delegatedPool = new Pool({ connectionString: roleUrl("helix_egress"), max: 6 });
  providers = new LiveProviders({
    databaseUrl: roleUrl("helix_egress"),
    reconcileIntervalMs: 5_000,
    log: { info: () => {}, warn: () => {}, error: () => {} },
  });
  await providers.start();
  egress = buildEgressApp({
    config: {
      port: 0,
      host: "127.0.0.1",
      databaseUrl: roleUrl("helix_egress"),
      statementTimeoutMs: 5_000,
      providersReconcileIntervalMs: 60_000,
      retireSweepIntervalMs: 60_000,
      instructionSecret: INSTRUCTION_SECRET,
      exchangeSecret: EXCHANGE_SECRET,
      limits: { maxBodyBytes: 1024 * 1024, timeoutMs: 5_000 },
      managedIdentityConnections: [],
      allowPrivate: true,
      allowInsecureConnection: true,
    },
    resolver: null,
    instructionKey,
    burnStore: null,
    exchange: {
      exchangeKey,
      providers,
      credentialStore: portalCustody,
      delegatedStore: delegatedCustody,
      allowPrivate: true,
      allowInsecureConnection: true,
      timeoutMs: 5_000,
    },
    delegated: {
      pool: delegatedPool,
      providers,
      credentialStore: portalCustody,
      delegatedStore: delegatedCustody,
      timeoutMs: 5_000,
      allowInsecureConnection: true,
    },
  });
  await egress.listen({ port: 0, host: "127.0.0.1" });
  const egressBaseUrl = `http://127.0.0.1:${(egress.server.address() as AddressInfo).port}`;
  process.env.PORTAL_EGRESS_URL = egressBaseUrl;
  process.env.PORTAL_ADMIN_GROUP_ID = ADMIN_GROUP;

  sweep = new CredentialRetirementSweep({
    pool: delegatedPool,
    delegatedStore: delegatedCustody,
    intervalMs: 50,
  });
  sweep.start();

  // The REAL portal, on the scratch database, holding the shared custody.
  portal = buildTestApp({
    prisma: createPrismaClient(JOURNEY_URL),
    secretStore: portalCustody,
    auth: {
      verifiers: [
        {
          verify: async (token) =>
            token === "owner"
              ? { oid: userOid, sub: "alice@azx.dev", via: "oidc", groups: [] }
              : token === "admin"
                ? {
                    oid: "journey-admin",
                    sub: "admin@azx.dev",
                    via: "oidc",
                    groups: [ADMIN_GROUP],
                  }
                : null,
        },
      ],
      publicConfig: null,
    },
  });
  await portal.app.ready();
  await portal.app.listen({ port: 0, host: "127.0.0.1" });
  const portalBaseUrl = `http://127.0.0.1:${(portal.app.server.address() as AddressInfo).port}`;

  // The REAL edge: the live registry projection (helix_edge), the real session
  // store and usage ledger, the real portal and egress seams over HTTP.
  liveRegistry = new LiveRegistry({
    databaseUrl: roleUrl("helix_edge"),
    reconcileIntervalMs: 60_000,
    log: {
      info: (...a) => console.log("REGISTRY:", ...a),
      warn: (...a) => console.log("REGISTRY-WARN:", ...a),
      error: (...a) => console.log("REGISTRY-ERROR:", ...a),
    },
  });
  await liveRegistry.start();
  sessionsStore = new PgSessionStore(roleUrl("helix_edge"), { max: 4 });
  const auth = testAuthConfig({ allowInsecureIdp: true });
  edge = buildEdgeApp({
    config: testEdgeConfig({
      auth,
      allowUnauthenticated: false,
      fetch: {
        egressUrl: egressBaseUrl,
        instructionSecret: INSTRUCTION_SECRET,
        timeoutMs: 10_000,
        maxBodyBytes: 1024 * 1024,
        maxAppInFlight: 0,
      },
      internalSecret: INTERNAL_SECRET,
      portalUrl: portalBaseUrl,
    }),
    registry: liveRegistry,
    blob: new FakeBlobReader(),
    sessions: sessionsStore,
    oidc: new FakeOidcClient(),
    usage: new PgUsageStore(roleUrl("helix_edge"), { max: 4 }),
    egress: new HttpEgressProvider(egressBaseUrl, { timeoutMs: 10_000 }),
    instructionKey,
    portal: new HttpPortalProvider(portalBaseUrl),
  });
  await edge.ready();

  // The REAL dev gateway: its own bearer tier, on the helix_dev role.
  devGateway = buildDevGateway({
    config: testDevGatewayConfig({
      fetch: {
        egressUrl: egressBaseUrl,
        instructionSecret: INSTRUCTION_SECRET,
        timeoutMs: 10_000,
        maxBodyBytes: 1024 * 1024,
        maxAppInFlight: 0,
      },
      internalSecret: INTERNAL_SECRET,
      portalUrl: portalBaseUrl,
    }),
    registry: liveRegistry,
    devTokens: new PgDevTokenStore(roleUrl("helix_dev")),
    appData: null,
    usage: new PgUsageStore(roleUrl("helix_dev"), { max: 4 }),
    llmProvider: null,
    egress: new HttpEgressProvider(egressBaseUrl, { timeoutMs: 10_000 }),
    instructionKey,
    portal: new HttpPortalProvider(portalBaseUrl),
  });
  await devGateway.ready();
}, 120_000);

afterAll(async () => {
  await sweep?.stop();
  await providers?.stop();
  await delegatedPool?.end();
  await egress?.close();
  await sessionsStore?.close();
  await edge?.close();
  await devGateway?.close();
  await portal?.close();
  await vendor?.close();
  await rotatingVendor?.close();
  await staticVendor?.close();
  for (const [i, t] of terminators.entries()) {
    // Drop keep-alive sockets (the browser agent's), then the listeners.
    for (const socket of terminatorSockets[i] ?? []) socket.destroy();
    await new Promise<void>((resolve) => t.close(() => resolve()));
  }
  await browserAgent.close();
  delete process.env.PORTAL_EGRESS_URL;
  delete process.env.PORTAL_ADMIN_GROUP_ID;
  try {
    execSync(
      `psql "${OWNER_URL.replace(/\/[^/]+$/, "/helix")}" -c "DROP DATABASE ${JOURNEY_DB} WITH (FORCE)"`,
      { stdio: "pipe" },
    );
  } catch {
    // A dropped-later scratch database is not a test failure.
  }
});

afterEach(() => {
  vendor?.resetTokenCalls();
  rotatingVendor?.resetTokenCalls();
  staticVendor?.resetTokenCalls();
});

// ── The journey ───────────────────────────────────────────────────────────────

describe("the prod consent journey through the real entry points", () => {
  it("start → consult → vendor authorize → callback → saved connection → delegated call in the configured placement", async () => {
    const f = await seedFixture("prod-journey", { envs: ["prod"], vendorToUse: vendor });
    const sessionCookie = await seedSession(f.appId);

    // 1 — the explicit start on the app host: a same-origin navigation from a
    // real session. The 302 IS the consult's success: the authorize URL
    // carries the protocol state the portal assembled from the SEALED client
    // identity it opened out of the shared custody.
    const start = await prodStart(f.slug, f.ref, sessionCookie);
    expect(start.status).toBe(302);
    const authorizeUrl = new URL(start.location as string);
    expect(authorizeUrl.protocol).toBe("https:");
    expect(authorizeUrl.pathname).toBe("/authorize");
    expect(authorizeUrl.searchParams.get("client_id")).toBe("journey-fixture-client");
    expect(authorizeUrl.searchParams.get("redirect_uri")).toBe(CALLBACK_URL);
    expect(authorizeUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorizeUrl.searchParams.get("state")).toBeTruthy();
    expect(authorizeUrl.searchParams.get("scope")).toBe("read write");

    // 2 — the browser approves at the vendor and lands on the fixed callback.
    const redirect = await vendorAuthorize(start.location as string);
    expect(redirect.state).toBe(authorizeUrl.searchParams.get("state"));

    // 3 — the callback through the edge's reverse proxy → portal → egress
    // exchange → CAS save: the completion page posts connected to the
    // recorded opener origin and closes.
    const done = await callbackThroughEdge(redirect);
    expect(done.status).toBe(200);
    expect(done.body).toContain('"outcome":"connected"');
    expect(done.body).toContain(`window.opener.postMessage(message, "${appOriginOf(f.slug)}")`);
    expect(done.body).toContain(`Connected to ${f.displayName}`);

    // 4 — the saved row, every field the journey earned.
    const row = await portal.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid, providerId: providerIdOf(f, "prod"), env: "prod" },
      },
    });
    expect(row.status).toBe("live");
    expect(row.grantedScopes).toEqual(["read", "write"]);
    expect(row.expiresAt.getTime()).toBeGreaterThan(Date.now() + 800_000);
    const material = await openMaterial(row.material);
    expect(material.access).toMatch(/^[A-Za-z0-9_-]{43}$/); // the fixture's token shape

    // 5 — the delegated call through the edge's fetch gateway → real egress →
    // the fixture's API destination: the token arrives in the configured
    // placement.
    const call = await delegatedCall(f.slug, sessionCookie, `${vendor.issuer}/api/echo`);
    expect(call.status, call.body).toBe(200);
    const echo = JSON.parse(call.body) as { placement: string; token: string | null };
    expect(echo.placement).toBe("header-bearer");
    expect(echo.token).toBe(material.access);

    // 6 — usage accounting + identity attribution on the real metered row.
    const ledger = await gatewayRow(f.appId, "ok");
    expect(ledger.userOid).toBe(userOid);
    expect(ledger.userKind).toBe("user");
    expect(ledger.userName).toBe("Alice Anders");
    expect(ledger.userEmail).toBe("alice@azx.dev");
    expect(ledger.capability).toBe("fetch");
    expect(ledger.model).toBe(vendor.issuer);
    expect(ledger.path).toBe("/api/echo");
    expect(ledger.method).toBe("POST");
    expect(ledger.statusCode).toBe(200);
  }, 30_000);
});

describe("the connection-status read tracks the journey (ADR-0031 as amended)", () => {
  it("not_connected before consent → connected after the callback → not_connected after disconnect", async () => {
    const f = await seedFixture("status-journey", { envs: ["prod"], vendorToUse: vendor });
    const sessionCookie = await seedSession(f.appId);

    // Before consent: the read answers not_connected — the condition under
    // which a delegated call would answer connection_required.
    const before = await statusRead(f.slug, f.ref, sessionCookie);
    expect(before.status).toBe(200);
    expect(before.body).toEqual({ status: "not_connected" });
    // Nothing was written: no attempt exists for a status read.
    expect(
      await portal.prisma.connectionConsentAttempt.count({
        where: { providerId: providerIdOf(f, "prod") },
      }),
    ).toBe(0);

    // Connect through the FULL journey — the read never shortcuts consent.
    const done = await connectJourney(f, { env: "prod", sessionCookie });
    expect(done.body).toContain('"outcome":"connected"');

    const after = await statusRead(f.slug, f.ref, sessionCookie);
    expect(after.body).toEqual({ status: "connected" });
    // The invariant, both directions: the delegated call dispatches while the
    // read says connected…
    const call = await delegatedCall(f.slug, sessionCookie, `${vendor.issuer}/api/echo`);
    expect(call.status).toBe(200);

    // …and after a My Connections disconnect the read is not_connected again,
    // matching the call's connection_required.
    const row = await portal.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid, providerId: providerIdOf(f, "prod"), env: "prod" },
      },
    });
    const gone = await portalApi("DELETE", `/api/v1/connections/mine/${row.id}`, "owner");
    expect(gone.body).toEqual({ outcome: "disconnected" });
    const disconnected = await statusRead(f.slug, f.ref, sessionCookie);
    expect(disconnected.body).toEqual({ status: "not_connected" });

    // An unbound ref never answers about connection state — not_available.
    const unbound = await statusRead(f.slug, "not-a-bound-provider", sessionCookie);
    expect(unbound.status).toBe(200);
    expect(unbound.body).toEqual({ status: "not_available" });

    // A signed-out caller gets 401, never a state.
    const anon = await statusRead(f.slug, f.ref, "not-a-session-token");
    expect(anon.status).toBe(401);
  }, 30_000);

  it("the dev tier's status read keys to the developer identity through the dev gateway", async () => {
    const f = await seedFixture("status-dev-journey", {
      envs: ["dev"],
      vendorToUse: vendor,
      devToken: true,
    });

    const before = await devStatusRead(f.slug, f.ref, f.devToken as string);
    expect(before.status).toBe(200);
    expect(before.body).toEqual({ status: "not_connected" });

    const done = await connectJourney(f, { env: "dev", devToken: f.devToken });
    expect(done.body).toContain('"outcome":"connected"');
    const after = await devStatusRead(f.slug, f.ref, f.devToken as string);
    expect(after.body).toEqual({ status: "connected" });
  }, 30_000);
});

describe("the dev-tier journey", () => {
  it("bearer POST → single-use popup URL → nonce entry → vendor → completion keyed to the developer identity", async () => {
    const f = await seedFixture("dev-journey", {
      envs: ["dev"],
      vendorToUse: vendor,
      devToken: true,
    });

    // 1 — the dev app's page POSTs with its bearer token and gets the one-time
    // popup URL: auth host + the entry path + the nonce, nothing else — the
    // bearer token never appears in any URL.
    const start = await devGateway.inject({
      method: "POST",
      url: `/${f.slug}/_api/connections/${f.ref}/start`,
      headers: { authorization: `Bearer ${f.devToken}`, origin: DEV_ORIGIN },
    });
    expect(start.statusCode).toBe(200);
    const started = DevConsentStartResponseSchema.parse(start.json());
    const popupUrl = popupUrlOf(started);
    const popup = new URL(popupUrl);
    expect(popup.origin).toBe(`https://${AUTH_HOST}:8080`);
    expect(popup.pathname).toBe(CONSENT_NONCE_ENTRY_PATH);
    expect([...popup.searchParams.keys()]).toEqual(["nonce"]);
    expect(popupUrl).not.toContain(f.devToken as string);

    // 2 — the popup opens the nonce entry (through the edge's auth-host proxy)
    // and is redirected straight to the vendor.
    const entry = await openPopup(popupUrl);
    expect(entry.status).toBe(302);
    expect(entry.location).toMatch(/^https:\/\/localhost:\d+\/authorize/);

    // 3 — the browser approves; the callback completes the attempt.
    const redirect = await vendorAuthorize(entry.location as string);
    const done = await callbackThroughEdge(redirect);
    expect(done.status).toBe(200);
    expect(done.body).toContain('"outcome":"connected"');
    // The completion message targets the DEV caller's validated origin —
    // recorded at the consult, delivered here end to end.
    expect(done.body).toContain(`window.opener.postMessage(message, "${DEV_ORIGIN}")`);

    // 4 — the row keys to the developer identity in the dev environment: the
    // dev token's developerOid (the minting owner's portal oid), env 'dev'.
    const row = await portal.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid, providerId: providerIdOf(f, "dev"), env: "dev" },
      },
    });
    expect(row.status).toBe("live");
    expect(row.userOid).toBe(userOid);

    // 5 — the replayed popup URL is refused after first use.
    const replay = await openPopup(popupUrl);
    expect(replay.status).toBe(200);
    expect(replay.location).toBeUndefined();
    expect(replay.body).toContain("isn't valid anymore");

    // 6 — the dev-tier delegated call rides the same identity through the dev
    // gateway: the vendor sees the dev connection's token.
    const call = await devDelegatedCall(f.slug, f.devToken as string, `${vendor.issuer}/api/echo`);
    expect(call.status).toBe(200);
    const echo = JSON.parse(call.body) as { placement: string; token: string | null };
    expect(echo.placement).toBe("header-bearer");
    expect(echo.token).toBe(await openMaterial(row.material).then((m) => m.access));

    // Attribution in the dev tier: the developer oid, kind `dev`, no display half.
    const ledger = await gatewayRow(f.appId, "ok");
    expect(ledger.userOid).toBe(userOid);
    expect(ledger.userKind).toBe("dev");
    expect(ledger.userName).toBeNull();
  }, 30_000);
});

describe("development and production separation", () => {
  it("a dev connection and a prod connection never serve each other's tier", async () => {
    const f = await seedFixture("env-split", {
      envs: ["prod", "dev"],
      vendorToUse: vendor,
      devToken: true,
    });
    const sessionCookie = await seedSession(f.appId);

    // The same principal connects in BOTH tiers (same user, same ref) — each
    // through its own tier's real entry points.
    const prodDone = await connectJourney(f, { env: "prod", sessionCookie });
    expect(prodDone.body).toContain('"outcome":"connected"');
    const devDone = await connectJourney(f, { env: "dev", devToken: f.devToken });
    expect(devDone.body).toContain('"outcome":"connected"');

    // Two rows: one per tier, independently usable.
    const prodRow = await portal.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid, providerId: providerIdOf(f, "prod"), env: "prod" },
      },
    });
    const devRow = await portal.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid, providerId: providerIdOf(f, "dev"), env: "dev" },
      },
    });
    expect(prodRow.id).not.toBe(devRow.id);

    // Disconnect the PROD connection: the prod call loses its connection…
    const mine = await portalApi("GET", "/api/v1/connections/mine", "owner");
    const card = (mine.body.connections as Array<{ id: string; env: string }>).find(
      (c) => c.env === "prod",
    );
    expect(card).toBeTruthy();
    const gone = await portalApi("DELETE", `/api/v1/connections/mine/${card?.id}`, "owner");
    expect(gone.body).toEqual({ outcome: "disconnected" });

    const prodCall = await delegatedCall(f.slug, sessionCookie, `${vendor.issuer}/api/echo`);
    expect(prodCall.status).toBe(403);
    const prodError = JSON.parse(prodCall.body) as { code: string; provider: { ref: string } };
    expect(prodError.code).toBe("connection_required");
    expect(prodError.provider.ref).toBe(f.ref);

    // …while the DEV connection is untouched and still serves its tier.
    const devCall = await devDelegatedCall(
      f.slug,
      f.devToken as string,
      `${vendor.issuer}/api/echo`,
    );
    expect(devCall.status).toBe(200);
    const devEcho = JSON.parse(devCall.body) as { token: string | null };
    expect(devEcho.token).toBe(await openMaterial(devRow.material).then((m) => m.access));
  }, 30_000);
});

describe("two approved apps share one connection", () => {
  it("the second app's consult answers already-connected and its calls ride the same connection", async () => {
    const f = await seedFixture("shared", { envs: ["prod"], vendorToUse: vendor });
    const sessionCookie = await seedSession(f.appId);

    // App A connects.
    const prodDone = await connectJourney(f, { env: "prod", sessionCookie });
    expect(prodDone.body).toContain('"outcome":"connected"');
    const grantsBefore = vendor
      .tokenCalls()
      .filter((c) => c.grantType === "authorization_code").length;

    // App B: same user, same provider — a second approved app.
    const bSlug = uniqueSlug("journey");
    const created = await portalApi("POST", "/api/v1/apps", "owner", {
      slug: bSlug,
      displayName: "Journey app B",
      visibility: { mode: "internal" },
    });
    expect(created.statusCode).toBe(201);
    const appIdB = (created.body as { id: string }).id;
    await seedLiveVersion(appIdB);
    const put = await portalApi("PUT", `/api/v1/apps/${bSlug}/manifest`, "owner", {
      capabilities: {
        mcp: [],
        externalOrigins: [],
        fetch: { shim: false, origins: [{ origin: vendor.issuer, provider: f.ref }] },
      },
    });
    expect(put.statusCode).toBe(200);
    expect(
      (await portalApi("POST", `/api/v1/approvals/${put.body.pending as string}/approve`, "admin"))
        .statusCode,
    ).toBe(200);
    await waitForRegistry(bSlug);

    // B's start CANNOT reach the vendor: already-connected — no second
    // consent round-trip, no second connection.
    const sessionB = await seedSession(appIdB);
    const startB = await prodStart(bSlug, f.ref, sessionB);
    expect(startB.status).toBe(200);
    expect(startB.body).toContain("Already connected");
    expect(startB.location).toBeUndefined();
    expect(vendor.tokenCalls().filter((c) => c.grantType === "authorization_code")).toHaveLength(
      grantsBefore,
    );
    expect(
      await portal.prisma.userConnection.count({
        where: { userOid, providerId: providerIdOf(f, "prod"), env: "prod" },
      }),
    ).toBe(1);

    // B's delegated call rides the shared connection — and the vendor's echo
    // reports the token and nothing else: neither app's identity travels
    // beyond it.
    const call = await delegatedCall(bSlug, sessionB, `${vendor.issuer}/api/echo`);
    expect(call.status).toBe(200);
    const echo = JSON.parse(call.body) as Record<string, unknown>;
    expect(Object.keys(echo).sort()).toEqual([
      "headerName",
      "method",
      "path",
      "placement",
      "token",
    ]);
  }, 30_000);
});

describe("both rotation modes through real expiry", () => {
  it("rotating: the renewal replaces the material, ledger-marks the old, and the call succeeds", async () => {
    const f = await seedFixture("rotating", { envs: ["prod"], vendorToUse: rotatingVendor });
    const sessionCookie = await seedSession(f.appId);
    const prodDone = await connectJourney(f, { env: "prod", sessionCookie });
    expect(prodDone.body).toContain('"outcome":"connected"');

    const row = await portal.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid, providerId: providerIdOf(f, "prod"), env: "prod" },
      },
    });
    // The SEALED references (what the ledger mark and the sweep's destroy
    // carry) — distinct from the plaintext `openMaterial` gives back.
    const sealedOld = ConnectionMaterialSchema.parse(JSON.parse(row.material));
    const first = await openMaterial(row.material);
    expect(row.pendingRetire).toBeNull();

    // Real expiry: wait out the one-second TTL on the row's own recorded
    // expiry (arrange-time knob), then the delegated call renews FIRST and
    // succeeds invisibly.
    await pollUntil(
      async () => (Date.now() < row.expiresAt.getTime() + 50 ? null : true),
      "the access token's recorded expiry",
    );
    const call = await delegatedCall(f.slug, sessionCookie, `${rotatingVendor.issuer}/api/echo`);
    expect(call.status).toBe(200);

    // The vendor saw exactly one refresh grant; the row swapped to fresh
    // material. The rotation's OLD material is ledger-marked in the same
    // UPDATE — and the sweep (this suite's, on its 50 ms cadence) may already
    // have claimed and destroyed it by the time this read lands, so the
    // race-free observable for the mark is the destroy itself.
    expect(rotatingVendor.tokenCalls().filter((c) => c.grantType === "refresh_token")).toHaveLength(
      1,
    );
    const renewed = await portal.prisma.userConnection.findUniqueOrThrow({ where: { id: row.id } });
    expect(renewed.status).toBe("live");
    expect(renewed.expiresAt.getTime()).toBeGreaterThan(row.expiresAt.getTime());
    expect(renewed.lastRenewedAt).toBeTruthy();
    const fresh = await openMaterial(renewed.material);
    expect(fresh.access).not.toBe(first.access);
    expect(fresh.refresh).not.toBe(first.refresh);
    await pollUntil(
      async () =>
        destroyed.includes(sealedOld.access) && destroyed.includes(sealedOld.refresh) ? true : null,
      "the sweep retiring the rotation's replaced material",
    );
    // The echo carries the RENEWED token.
    const echo = JSON.parse(call.body) as { token: string | null };
    expect(echo.token).toBe(fresh.access);
  }, 30_000);

  it("non-rotating: the renewal retains the refresh token, writes no ledger mark, and the call succeeds", async () => {
    const f = await seedFixture("non-rotating", { envs: ["prod"], vendorToUse: staticVendor });
    const sessionCookie = await seedSession(f.appId);
    const prodDone = await connectJourney(f, { env: "prod", sessionCookie });
    expect(prodDone.body).toContain('"outcome":"connected"');

    const row = await portal.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid, providerId: providerIdOf(f, "prod"), env: "prod" },
      },
    });
    const first = await openMaterial(row.material);

    await pollUntil(
      async () => (Date.now() < row.expiresAt.getTime() + 50 ? null : true),
      "the access token's recorded expiry",
    );
    const call = await delegatedCall(f.slug, sessionCookie, `${staticVendor.issuer}/api/echo`);
    expect(call.status).toBe(200);

    expect(staticVendor.tokenCalls().filter((c) => c.grantType === "refresh_token")).toHaveLength(
      1,
    );
    const renewed = await portal.prisma.userConnection.findUniqueOrThrow({ where: { id: row.id } });
    const fresh = await openMaterial(renewed.material);
    expect(fresh.access).not.toBe(first.access); // the access token DID turn over…
    expect(fresh.refresh).toBe(first.refresh); // …the refresh token was RETAINED
    expect(renewed.pendingRetire).toBeNull(); // retain-on-omission: no ledger entry
    expect(renewed.lastRenewedAt).toBeTruthy();
  }, 30_000);
});

describe("disconnection, sensitive edits, deletion", () => {
  it("disconnect stops use immediately; the ledger labels connection_required apart from refusal", async () => {
    const f = await seedFixture("disconnect", { envs: ["prod"], vendorToUse: vendor });
    const sessionCookie = await seedSession(f.appId);
    const prodDone = await connectJourney(f, { env: "prod", sessionCookie });
    expect(prodDone.body).toContain('"outcome":"connected"');

    const row = await portal.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid, providerId: providerIdOf(f, "prod"), env: "prod" },
      },
    });
    const liveMaterial = ConnectionMaterialSchema.parse(JSON.parse(row.material));

    // Disconnect through My Connections (the caller's own connection)…
    const repeat = await portalApi("DELETE", `/api/v1/connections/mine/${row.id}`, "owner");
    expect(repeat.body).toEqual({ outcome: "disconnected" });
    // …and the repeat on the removed connection answers already_removed.
    const again = await portalApi("DELETE", `/api/v1/connections/mine/${row.id}`, "owner");
    expect(again.body).toEqual({ outcome: "already_removed" });

    // Use stops immediately: the next delegated call answers
    // connection_required with the provider metadata the app needs to offer
    // Connect.
    const call = await delegatedCall(f.slug, sessionCookie, `${vendor.issuer}/api/echo`);
    expect(call.status).toBe(403);
    const err = JSON.parse(call.body) as {
      code: string;
      provider: { ref: string; displayName: string };
    };
    expect(FETCH_ERROR_CODES).toContain(err.code);
    expect(err.code).toBe("connection_required");
    expect(err.provider).toEqual({ ref: f.ref, displayName: f.displayName });

    // …and the LEDGER separates it from a policy refusal: this
    // row is connection_required; the deletion leg's row below is refusal.
    const required = await gatewayRow(f.appId, "connection_required");
    expect(required.statusCode).toBe(403);
    expect(required.userOid).toBe(userOid);
    expect(required.outcome).toBe("connection_required");

    // Cleanup within the sweep's cadence bound: the row's ledger mark is
    // claimed and the material is handed to the delegated store's destroy —
    // asserted by polling the observable, never by waiting wall-clock minutes.
    await pollUntil(
      async () =>
        destroyed.includes(liveMaterial.access) && destroyed.includes(liveMaterial.refresh)
          ? true
          : null,
      "the sweep destroying the disconnected material",
    );
    const swept = await portal.prisma.userConnection.findUniqueOrThrow({ where: { id: row.id } });
    expect(swept.status).toBe("invalidated");
    expect(swept.pendingRetire).toBeNull();
  }, 30_000);

  it("a sensitive edit mid-consent kills the attempt — the callback cannot establish anything", async () => {
    const f = await seedFixture("edit-attempt", { envs: ["prod"], vendorToUse: vendor });
    const sessionCookie = await seedSession(f.appId);

    // A consent attempt is pending…
    const start = await prodStart(f.slug, f.ref, sessionCookie);
    expect(start.status).toBe(302);
    expect(
      await portal.prisma.connectionConsentAttempt.count({
        where: { providerId: providerIdOf(f, "prod") },
      }),
    ).toBe(1);

    // …the administrator applies a sensitive edit (confirmed)…
    const put = await portalApi("PUT", `/api/v1/providers/${providerIdOf(f, "prod")}`, "admin", {
      displayName: f.displayName,
      authorizeEndpoint: `https://localhost:${terminatorPortOf(vendor)}/authorize`,
      tokenEndpoint: `${vendor.issuer}/token`,
      requestedScopes: ["read"], // sensitive: the requested permissions changed
      apiOrigins: [vendor.issuer],
      tokenPlacement: { kind: "header-bearer" },
      revision: f.providerRevision,
      confirmInvalidation: true,
    });
    expect(put.statusCode).toBe(200);
    expect(put.body.revision).toBe(f.providerRevision + 1);

    // …and the vendor's redirect can no longer establish: the attempt died
    // with the edit, and nothing is saved.
    const redirect = await vendorAuthorize(start.location as string);
    const done = await callbackThroughEdge(redirect);
    expect(done.status).toBe(200);
    expect(done.body).not.toContain('"outcome":"connected"');
    expect(done.body).toContain("This attempt was cancelled.");
    expect(
      await portal.prisma.userConnection.count({ where: { providerId: providerIdOf(f, "prod") } }),
    ).toBe(0);

    // The blocked binding cannot be bypassed by starting again: the
    // stale-dated stamp answers not_available.
    const restart = await prodStart(f.slug, f.ref, sessionCookie);
    expect(restart.status).toBe(200);
    expect(restart.body).toContain("Connection not available");

    // The recovery (the re-stamp amendment): the owner resubmits the manifest —
    // the SPA's "save to resubmit" is an unchanged PUT — and the write-gate
    // re-elevates the stale binding, filing a fresh stamp against the edit's
    // revision.
    const manifest = await portalApi("GET", `/api/v1/apps/${f.slug}/manifest`, "owner");
    expect(manifest.statusCode).toBe(200);
    const resubmit = await portalApi("PUT", `/api/v1/apps/${f.slug}/manifest`, "owner", {
      capabilities: manifest.body.capabilities,
    });
    expect(resubmit.statusCode).toBe(200);
    const resubmitId = resubmit.body.pending as string | null;
    expect(resubmitId).toBeTruthy();

    // The re-blessing is an administrator's, like the first grant.
    const approved = await portalApi(
      "POST",
      `/api/v1/approvals/${resubmitId}/approve`,
      "admin",
      {},
    );
    expect(approved.statusCode).toBe(200);

    // Egress's provider cache is NOTIFY-driven with a reconcile cadence — the
    // same eventual consistency the edge's registry projection has. The new
    // attempt will stamp the edit's revision, so wait for the cache to hold it
    // (an exchange against the stale cache answers provider_unavailable).
    // 15s, not the 5s default: the cache's own reconcile interval is 5s.
    await pollUntil(
      async () =>
        providers.get(providerIdOf(f, "prod"))?.revision === f.providerRevision + 1 ? true : null,
      "egress's provider cache catching up to the edited revision",
      15_000,
    );

    // And the binding serves again: the start consults effective stamps and
    // hands the popup to the vendor, whose consent (already granted earlier in
    // this flow) re-establishes the connection the edit killed.
    const recovered = await prodStart(f.slug, f.ref, sessionCookie);
    expect(recovered.status).toBe(302);
    const recoveredRedirect = await vendorAuthorize(recovered.location as string);
    const recoveredDone = await callbackThroughEdge(recoveredRedirect);
    expect(recoveredDone.status, recoveredDone.body).toBe(200);
    expect(recoveredDone.body).toContain('"outcome":"connected"');
    expect(
      await portal.prisma.userConnection.count({ where: { providerId: providerIdOf(f, "prod") } }),
    ).toBe(1);
  }, 30_000);

  it("a sensitive edit kills the live connection, and deletion makes later calls report provider unavailability", async () => {
    const f = await seedFixture("edit-conn", { envs: ["prod"], vendorToUse: vendor });
    const sessionCookie = await seedSession(f.appId);
    const prodDone = await connectJourney(f, { env: "prod", sessionCookie });
    expect(prodDone.body).toContain('"outcome":"connected"');

    // A confirmed sensitive edit (the requested permissions change) invalidates
    // the connection…
    const put = await portalApi("PUT", `/api/v1/providers/${providerIdOf(f, "prod")}`, "admin", {
      displayName: f.displayName,
      authorizeEndpoint: `https://localhost:${terminatorPortOf(vendor)}/authorize`,
      tokenEndpoint: `${vendor.issuer}/token`,
      requestedScopes: ["read", "write", "admin:wide"], // sensitive delta
      apiOrigins: [vendor.issuer],
      tokenPlacement: { kind: "header-bearer" },
      revision: f.providerRevision,
      confirmInvalidation: true,
    });
    expect(put.statusCode).toBe(200);

    // Wait out egress's provider cache (NOTIFY + reconcile cadence): a
    // delegated call against the stale cache answers provider_unavailable —
    // the wrong refusal for this leg, which is about the invalidated
    // CONNECTION, not the provider's identity.
    await pollUntil(
      async () =>
        providers.get(providerIdOf(f, "prod"))?.revision === f.providerRevision + 1 ? true : null,
      "egress's provider cache catching up to the edited revision",
      15_000,
    );

    // …which can never serve a call again (the resolution refuses a non-live
    // row) — while the edge still mints the instruction, because the edge
    // evaluates no provider state (observable end to end).
    const afterEdit = await delegatedCall(f.slug, sessionCookie, `${vendor.issuer}/api/echo`);
    expect(afterEdit.status).toBe(403);
    expect((JSON.parse(afterEdit.body) as { code: string }).code).toBe("connection_required");

    // The edit's retirement ledger mark is consumed by the sweep within the
    // cadence bound.
    const row = await portal.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid, providerId: providerIdOf(f, "prod"), env: "prod" },
      },
    });
    const deadMaterial = ConnectionMaterialSchema.parse(JSON.parse(row.material));
    await pollUntil(
      async () => (destroyed.includes(deadMaterial.access) ? true : null),
      "the sweep destroying the edited-away material",
    );

    // Deletion: confirmed, the row gone; delegated calls report
    // provider unavailability — the LEDGER records it as refusal, distinct
    // from the disconnect leg's connection_required label.
    const del = await portalApi("DELETE", `/api/v1/providers/${providerIdOf(f, "prod")}`, "admin", {
      confirmInvalidation: true,
    });
    expect(del.body).toEqual({ outcome: "deleted" });

    // The egress cache may hold the row for one NOTIFY's debounce — poll
    // until the unavailability class arrives.
    const afterDelete = await pollUntil(async () => {
      const res = await delegatedCall(f.slug, sessionCookie, `${vendor.issuer}/api/echo`);
      return res.status === 503 ? res : null;
    }, "the provider_unavailable answer");
    const delErr = JSON.parse(afterDelete.body) as { code: string; provider: { ref: string } };
    expect(delErr.code).toBe("provider_unavailable");
    expect(delErr.provider.ref).toBe(f.ref);

    const refused = await gatewayRow(f.appId, "refusal");
    expect(refused.statusCode).toBe(503);
    expect(refused.userOid).toBe(userOid);
    expect(refused.outcome).toBe("refusal");

    // And the consult agrees the feature is gone for this app (the blocked
    // binding); nothing restored either consent or connection.
    const restart = await prodStart(f.slug, f.ref, sessionCookie);
    expect(restart.body).toContain("Connection not available");
  }, 30_000);
});
