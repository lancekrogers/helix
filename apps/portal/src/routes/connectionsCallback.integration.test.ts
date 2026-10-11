import { randomBytes, randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import { SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { createSecretStore, DevEnvelopeSecretStore, type SecretStore } from "@azx-pbc/secret-store";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import {
  ConnectionMaterialSchema,
  ConnectionProviderSchema,
  type ConnectionProvider,
  INTERNAL_AUDIENCE,
  INTERNAL_AUTH_HEADER,
  INTERNAL_JWT_TYP,
  type ConsultRequest,
} from "@azx-pbc/shared";
import {
  ATTR_OUTCOME,
  CONSENT_CALLBACK_OUTCOMES,
  FORBIDDEN_URL_ATTRS,
  INSTR_CONSENT_OPERATIONS,
  SPAN_CONSENT_CALLBACK,
} from "@azx-pbc/shared/telemetry";
import { startDevOAuthVendor, type RunningDevOAuthVendor } from "@azx-pbc/dev-oauth-vendor";
import { buildApp as buildEgressApp } from "@azx-pbc/egress/app";
import { deriveExchangeKey, deriveInternalKey, resolveInternalSecret } from "../internalJwt.js";
import { connectionsCallbackUrl } from "../deployment.js";
import { buildTestApp, uniqueSlug, type TestApp } from "../test/harness.js";

/**
 * The consent callback end to end against the
 * REAL pieces: the fixture vendor issues the grant through a real
 * authorize round-trip, the portal's real callback route claims the attempt
 * (the claim probe), delegates the exchange over real HTTP to the REAL egress
 * app (the exchange operation, in-process on an ephemeral port), and saves with
 * the CAS/upsert contract. This is the OIDC-handoff class, so the adversarial
 * matrix ships with it: forged, reused, expired, cancelled,
 * declined, foreign-provider, and the concurrent race — none of
 * which may establish a row its scenario didn't earn.
 *
 * The test plays the browser the `flow.integration.test.ts` way: app.inject()
 * for the portal's own hops, real fetch for the vendor's. It never inserts a
 * finished connection to drive the callback — the row that appears is the
 * flow's output; seeded rows exist only as arrange-time state (a dead
 * connection for the replace and disconnect legs). Every DB assertion is
 * scoped to the case's own provider/app — suites run in parallel.
 */

const ADMIN_GROUP = "platform-admin";
const OID_TAG = randomUUID().slice(0, 8);
const userOid = `oid-callback-user-${OID_TAG}`;
const devOid = `oid-callback-developer-${OID_TAG}`;

const CLIENT_ID = "callback-fixture-client";
const CLIENT_SECRET = "callback-fixture-client-secret-4f2a";
const OPENER_ORIGIN = "https://app.example.test";

const INTERNAL_KEY = deriveInternalKey(resolveInternalSecret());
const CALLBACK_URL = connectionsCallbackUrl();
const EXCHANGE_KEY = deriveExchangeKey(
  Buffer.from(process.env.HELIX_EXCHANGE_SECRET ?? "", "utf8"),
);

const store = new DevEnvelopeSecretStore({ masterKey: randomBytes(32) });
const delegatedKek = randomBytes(32);

let vendor: RunningDevOAuthVendor;
let foreignVendor: RunningDevOAuthVendor;
let egress: FastifyInstance;
let t: TestApp;
let recording: RecordingTelemetry;

/** The provider row the egress cache serves — set per case, before its callback. */
let currentProvider: ConnectionProvider | undefined;
const providerReader = {
  get: (id: string) => (currentProvider && id === currentProvider.id ? currentProvider : undefined),
  getByRef: (ref: string, env: string) =>
    currentProvider && currentProvider.ref === ref && currentProvider.env === env
      ? currentProvider
      : undefined,
  isLoaded: () => true,
};

const createdProviderIds: string[] = [];
const createdRefs: string[] = [];
const createdSlugs: string[] = [];

interface Fixture {
  slug: string;
  ref: string;
  providerId: string;
  appId: string;
  displayName: string;
}

/** The everything-approved fixture (real routes), plus the egress-cache row. */
async function seededReady(
  tag: string,
  opts: {
    env?: "prod" | "dev";
    requestedScopes?: string[];
    /** Point the provider at a vendor instance (default: the suite's own). */
    vendor?: RunningDevOAuthVendor;
  } = {},
): Promise<Fixture> {
  const env = opts.env ?? "prod";
  const scopes = opts.requestedScopes ?? ["read", "write"];
  const target = opts.vendor ?? vendor;
  const ref = `b-${OID_TAG}-${tag}`;
  const slug = uniqueSlug("callback");
  createdRefs.push(ref);
  createdSlugs.push(slug);

  const created = await t.app.inject({
    method: "POST",
    url: "/api/v1/apps",
    headers: { authorization: "Bearer owner" },
    payload: { slug, displayName: "Callback fixture", visibility: { mode: "internal" } },
  });
  expect(created.statusCode).toBe(201);
  const appId = created.json().id as string;

  const provider = ConnectionProviderSchema.parse({
    id: randomUUID(),
    ref,
    kind: "rest-delegated",
    displayName: "Fixture Vendor",
    authorizeEndpoint: `${target.issuer}/authorize`,
    tokenEndpoint: `${target.issuer}/token`,
    requestedScopes: scopes,
    apiOrigins: ["https://api.fixture.test"],
    tokenPlacement: { kind: "header-bearer" },
    env,
    clientIdMaterial: await store.seal(CLIENT_ID),
    clientSecretMaterial: await store.seal(CLIENT_SECRET),
    revision: 1,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
  await t.prisma.connectionProvider.create({
    data: {
      id: provider.id,
      ref,
      kind: provider.kind,
      displayName: provider.displayName,
      authorizeEndpoint: provider.authorizeEndpoint,
      tokenEndpoint: provider.tokenEndpoint,
      requestedScopes: provider.requestedScopes,
      apiOrigins: provider.apiOrigins,
      tokenPlacement: provider.tokenPlacement,
      env,
      clientIdMaterial: provider.clientIdMaterial,
      clientSecretMaterial: provider.clientSecretMaterial,
      revision: provider.revision,
    },
  });
  createdProviderIds.push(provider.id);

  const put = await t.app.inject({
    method: "PUT",
    url: `/api/v1/apps/${slug}/manifest`,
    headers: { authorization: "Bearer owner" },
    payload: {
      capabilities: {
        mcp: [],
        externalOrigins: [],
        fetch: { shim: false, origins: [{ origin: "https://api.fixture.test", provider: ref }] },
      },
    },
  });
  expect(put.statusCode).toBe(200);
  const approve = await t.app.inject({
    method: "POST",
    url: `/api/v1/approvals/${put.json().pending}/approve`,
    headers: { authorization: "Bearer admin" },
  });
  expect(approve.statusCode).toBe(200);

  currentProvider = provider;
  return { slug, ref, providerId: provider.id, appId, displayName: provider.displayName };
}

/** The edge's consult call — the real pending-attempt write. */
async function consult(
  fixture: Fixture,
  identity: ConsultRequest["identity"],
): Promise<{ authorizeUrl: string; state: string }> {
  const internalToken = await new SignJWT({})
    .setProtectedHeader({ alg: "HS256", typ: INTERNAL_JWT_TYP })
    .setAudience(INTERNAL_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("30s")
    .sign(INTERNAL_KEY);
  const res = await t.app.inject({
    method: "POST",
    url: "/internal/connections/consult",
    headers: { [INTERNAL_AUTH_HEADER]: internalToken, "content-type": "application/json" },
    payload: {
      identity,
      appSlug: fixture.slug,
      providerRef: fixture.ref,
      openerOrigin: OPENER_ORIGIN,
      callbackUrl: CALLBACK_URL,
    } satisfies ConsultRequest,
  });
  expect(res.statusCode).toBe(200);
  expect(res.json().outcome).toBe("started");
  const authorizeUrl = res.json().authorizeUrl as string;
  const state = new URL(authorizeUrl).searchParams.get("state");
  expect(state).toBeTruthy();
  return { authorizeUrl, state: state as string };
}

/**
 * Play the browser at the vendor's authorize screen and follow the redirect to
 * the fixed callback. `scope` rewrites the authorize request's scope — what a
 * user granting fewer permissions than asked looks like (a short
 * grant).
 */
async function authorizeAndRedirect(
  authorizeUrl: string,
  opts: { scope?: string } = {},
): Promise<{ code: string | null; error: string | null; state: string | null }> {
  const target = new URL(authorizeUrl);
  if (opts.scope !== undefined) target.searchParams.set("scope", opts.scope);
  const res = await fetch(target, { redirect: "manual" });
  await res.body?.cancel();
  expect(res.status).toBe(302);
  const location = res.headers.get("location");
  expect(location).toBeTruthy();
  expect(new URL(location as string).pathname).toBe("/connections/callback");
  const params = new URL(location as string).searchParams;
  return {
    code: params.get("code"),
    error: params.get("error"),
    state: params.get("state"),
  };
}

/** The fixed callback through the real portal route. */
async function callback(query: Record<string, string>): Promise<{
  status: number;
  body: string;
  headers: Record<string, unknown>;
}> {
  const res = await t.app.inject({
    method: "GET",
    url: `/connections/callback?${new URLSearchParams(query).toString()}`,
  });
  return { status: res.statusCode, body: res.body, headers: res.headers };
}

const prodIdentity = { kind: "user" as const, userOid };

let egressBaseUrl = "";

beforeAll(async () => {
  process.env.PORTAL_ADMIN_GROUP_ID = ADMIN_GROUP;
  recording = startRecordingTelemetry();
  t = buildTestApp({
    auth: {
      verifiers: [
        {
          verify: async (token) =>
            token === "owner"
              ? { oid: userOid, sub: "owner@azx.io", via: "oidc", groups: [] }
              : token === "admin"
                ? { oid: "oid-admin", sub: "admin@azx.io", via: "oidc", groups: [ADMIN_GROUP] }
                : null,
        },
      ],
      publicConfig: null,
    },
    secretStore: store,
  });
  await t.app.ready();

  vendor = await startDevOAuthVendor({
    accessTokenTtlSeconds: 900,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  });
  foreignVendor = await startDevOAuthVendor({
    accessTokenTtlSeconds: 900,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  });

  // The REAL egress app (the exchange operation) on an ephemeral port, with the
  // same exchange secret the portal derives its mint key from, custody over
  // the same sealed credentials, and a dedicated delegated store. The suite
  // points `currentProvider` at each case's row — the exchange.test.ts shape,
  // minus the handler injection: this is the composed HTTP service.
  const delegated: SecretStore = createSecretStore({ devMasterKey: delegatedKek });
  egress = buildEgressApp({
    config: {
      port: 0,
      host: "127.0.0.1",
      databaseUrl: "",
      statementTimeoutMs: 5_000,
      providersReconcileIntervalMs: 60_000,
      retireSweepIntervalMs: 60_000,
      instructionSecret: randomBytes(48),
      exchangeSecret: Buffer.from(process.env.HELIX_EXCHANGE_SECRET ?? "", "utf8"),
      limits: { maxBodyBytes: 1024 * 1024, timeoutMs: 5_000, llmTimeoutMs: 30_000 },
      managedIdentityConnections: [],
      allowPrivate: true,
      extraBlockedCidrs: [],
      allowInsecureConnection: true,
    },
    resolver: null,
    instructionKey: randomBytes(48),
    burnStore: null,
    exchange: {
      exchangeKey: EXCHANGE_KEY,
      providers: providerReader,
      credentialStore: store,
      delegatedStore: delegated,
      allowPrivate: true,
      allowInsecureConnection: true,
      timeoutMs: 5_000,
    },
  });
  await egress.listen({ port: 0, host: "127.0.0.1" });
  const port = (egress.server.address() as AddressInfo).port;
  egressBaseUrl = `http://127.0.0.1:${port}`;
  process.env.PORTAL_EGRESS_URL = egressBaseUrl;
});

afterEach(() => {
  recording.reset();
  currentProvider = undefined;
  vendor.setModes({ tokenMode: "rotating", authorizeMode: "approve" });
});

afterAll(async () => {
  await t.prisma.connectionConsentAttempt.deleteMany({
    where: { providerId: { in: createdProviderIds } },
  });
  await t.prisma.userConnection.deleteMany({
    where: { providerId: { in: createdProviderIds } },
  });
  const apps = await t.prisma.app.findMany({ where: { slug: { in: createdSlugs } } });
  await t.prisma.auditEvent.deleteMany({
    where: { action: "connection.connected", appId: { in: apps.map((a) => a.id) } },
  });
  await t.prisma.approvalRequest.deleteMany({ where: { app: { slug: { in: createdSlugs } } } });
  await t.prisma.app.deleteMany({ where: { slug: { in: createdSlugs } } });
  await t.prisma.connectionProvider.deleteMany({ where: { ref: { in: createdRefs } } });
  await t.close();
  await egress.close();
  await vendor.close();
  await foreignVendor.close();
  await recording.restore();
  delete process.env.PORTAL_EGRESS_URL;
});

/** Open a row's material envelope through the delegated custody's KEK. */
async function openMaterial(material: string): Promise<{ access: string; refresh: string }> {
  const envelope = ConnectionMaterialSchema.parse(JSON.parse(material));
  const opened = createSecretStore({ devMasterKey: delegatedKek });
  return {
    access: await opened.open(envelope.access),
    refresh: await opened.open(envelope.refresh),
  };
}

describe("the happy path — real vendor, real attempt, real callback", () => {
  it("saves the connection and the page posts connected to the recorded opener", async () => {
    const fixture = await seededReady("happy");
    const { authorizeUrl, state } = await consult(fixture, prodIdentity);
    const redirect = await authorizeAndRedirect(authorizeUrl);
    expect(redirect.code).toBeTruthy();

    const res = await callback({ code: redirect.code as string, state });
    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");

    // The page: posts the connected message to the RECORDED opener origin and
    // closes itself; the success line is the fallback.
    expect(res.body).toContain(`window.opener.postMessage(message, "${OPENER_ORIGIN}")`);
    expect(res.body).toContain('"outcome":"connected"');
    expect(res.body).toContain("window.close()");
    expect(res.body).toContain(`Connected to ${fixture.displayName} — you can return to the app.`);
    expect(res.body).toContain('id="helix-connect-fallback" hidden');
    expect(res.body).toContain(
      '<button type="button" class="close" id="helix-connect-close">Close</button>',
    );
    expect(res.body).toContain('<h1 tabindex="-1">');
    // No protocol material on the page, ever.
    expect(res.body).not.toContain(state);
    expect(res.body).not.toContain(redirect.code as string);

    // The row: one connection, every saved field the contract names.
    const row = await t.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid, providerId: fixture.providerId, env: "prod" },
      },
    });
    expect(row.status).toBe("live");
    expect(row.providerRevision).toBe(1);
    expect(row.grantedScopes).toEqual(["read", "write"]);
    expect(row.expiresAt.getTime()).toBeGreaterThan(Date.now() + 800_000);
    expect(row.pendingRetire).toBeNull();
    expect(row.renewBeforeNext).toBe(false);
    const material = await openMaterial(row.material);
    expect(material.access).toMatch(/^[A-Za-z0-9_-]{43}$/); // the fixture's token shape
    expect(material.refresh).toMatch(/^[A-Za-z0-9_-]{43}$/);

    // The attempt is consumed — for this provider.
    expect(
      await t.prisma.connectionConsentAttempt.findMany({
        where: { providerId: fixture.providerId },
      }),
    ).toEqual([]);

    // The audit event, bounded.
    const audit = await t.prisma.auditEvent.findFirstOrThrow({
      where: { action: "connection.connected", appId: fixture.appId },
    });
    expect(audit.actor).toBe(userOid);
    expect(audit.metadata).toEqual({
      providerRef: fixture.ref,
      env: "prod",
      appId: fixture.appId,
    });
  });

  it("completes the dev journey's attempt into the dev tier", async () => {
    const fixture = await seededReady("dev", { env: "dev" });
    const { authorizeUrl, state } = await consult(fixture, {
      kind: "dev",
      developerOid: devOid,
      nonce: `nonce-${OID_TAG}-dev-callback`,
    });
    const redirect = await authorizeAndRedirect(authorizeUrl);
    const res = await callback({ code: redirect.code as string, state });
    expect(res.status).toBe(200);
    expect(res.body).toContain('"outcome":"connected"');

    const row = await t.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid: devOid, providerId: fixture.providerId, env: "dev" },
      },
    });
    expect(row.env).toBe("dev");
    expect(row.status).toBe("live");
  });
});

describe("the adversarial matrix — nothing establishes", () => {
  it("a forged state renders the fixed refusal, consumes nothing, saves nothing", async () => {
    const fixture = await seededReady("forged");
    const res = await callback({
      code: "forged-code",
      state: `forged-${OID_TAG}-000000000000000000000000000000`,
    });
    expect(res.status).toBe(200);
    // The fixed refusal page: no message target, no provider name, no post.
    expect(res.body).not.toContain("postMessage");
    expect(res.body).toContain("isn't valid anymore");
    expect(await t.prisma.userConnection.count({ where: { providerId: fixture.providerId } })).toBe(
      0,
    );
    expect(
      await t.prisma.auditEvent.count({
        where: { action: "connection.connected", appId: fixture.appId },
      }),
    ).toBe(0);
  });

  it("a reused state cannot complete twice — the second render is the refusal", async () => {
    const fixture = await seededReady("reused");
    const { authorizeUrl, state } = await consult(fixture, prodIdentity);
    const redirect = await authorizeAndRedirect(authorizeUrl);
    expect((await callback({ code: redirect.code as string, state })).status).toBe(200);

    const second = await callback({ code: redirect.code as string, state });
    expect(second.status).toBe(200);
    expect(second.body).not.toContain('"outcome":"connected"');
    expect(await t.prisma.userConnection.count({ where: { providerId: fixture.providerId } })).toBe(
      1,
    );
    expect(
      await t.prisma.auditEvent.count({
        where: { action: "connection.connected", appId: fixture.appId },
      }),
    ).toBe(1);
  });

  it("an expired attempt renders the expired page and saves nothing", async () => {
    const fixture = await seededReady("expired");
    const { authorizeUrl, state } = await consult(fixture, prodIdentity);
    await t.prisma.connectionConsentAttempt.update({
      where: { state },
      data: { expiresAt: new Date(Date.now() - 1) },
    });
    const redirect = await authorizeAndRedirect(authorizeUrl);
    const res = await callback({ code: redirect.code as string, state });
    expect(res.status).toBe(200);
    expect(res.body).toContain("This attempt expired (5 minutes)");
    // The refusal posts timeout to the recorded opener — the app's wait ends
    // legibly (timeout is distinguishable to the app).
    expect(res.body).toContain(`window.opener.postMessage(message, "${OPENER_ORIGIN}")`);
    expect(res.body).toContain('"outcome":"timeout"');
    expect(await t.prisma.userConnection.count({ where: { providerId: fixture.providerId } })).toBe(
      0,
    );
  });

  it("a cancelled attempt renders the cancelled page and saves nothing", async () => {
    const fixture = await seededReady("cancelled");
    const { authorizeUrl, state } = await consult(fixture, prodIdentity);
    const internalToken = await new SignJWT({})
      .setProtectedHeader({ alg: "HS256", typ: INTERNAL_JWT_TYP })
      .setAudience(INTERNAL_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime("30s")
      .sign(INTERNAL_KEY);
    const cancel = await t.app.inject({
      method: "POST",
      url: "/internal/connections/cancel",
      headers: { [INTERNAL_AUTH_HEADER]: internalToken, "content-type": "application/json" },
      payload: { identity: prodIdentity, state },
    });
    expect(cancel.json()).toEqual({ outcome: "cancelled" });
    const redirect = await authorizeAndRedirect(authorizeUrl);
    const res = await callback({ code: redirect.code as string, state });
    expect(res.status).toBe(200);
    expect(res.body).toContain("This attempt was cancelled.");
    expect(await t.prisma.userConnection.count({ where: { providerId: fixture.providerId } })).toBe(
      0,
    );
  });

  it("a foreign provider's code cannot complete the attempt (mix-up defense)", async () => {
    const fixture = await seededReady("mixup", { vendor });
    const { state } = await consult(fixture, prodIdentity);
    // A real grant code — but from ANOTHER provider's vendor instance,
    // redirected at the fixed callback under this attempt's state.
    const foreignUrl = new URL(`${foreignVendor.issuer}/authorize`);
    foreignUrl.searchParams.set("client_id", CLIENT_ID);
    foreignUrl.searchParams.set("response_type", "code");
    foreignUrl.searchParams.set("redirect_uri", CALLBACK_URL);
    foreignUrl.searchParams.set("code_challenge", randomBytes(32).toString("base64url"));
    foreignUrl.searchParams.set("code_challenge_method", "S256");
    foreignUrl.searchParams.set("state", state);
    const foreignRedirect = await authorizeAndRedirect(foreignUrl.toString());
    expect(foreignRedirect.code).toBeTruthy();

    const res = await callback({ code: foreignRedirect.code as string, state });
    expect(res.status).toBe(503); // the service-failure posture
    expect(res.body).toContain("Couldn&#39;t complete the connection — try again from the app.");
    expect(res.body).not.toContain("invalid_grant"); // no vendor error text, ever
    expect(await t.prisma.userConnection.count({ where: { providerId: fixture.providerId } })).toBe(
      0,
    );
  });

  it("carries no code, state, verifier, or identity on any span attribute", async () => {
    const fixture = await seededReady("redact");
    const { authorizeUrl, state } = await consult(fixture, prodIdentity);
    const redirect = await authorizeAndRedirect(authorizeUrl);
    await callback({ code: redirect.code as string, state });

    // The global scan — every attribute of every span, both planes' (the real
    // egress app records into the same providers).
    const dump = JSON.stringify(
      recording.spans().map((s) => ({ name: s.name, attrs: s.attributes })),
    );
    expect(dump).not.toContain(state);
    expect(dump).not.toContain(redirect.code as string);
    expect(dump).not.toContain(userOid);
    expect(dump).not.toContain(CLIENT_SECRET);
    for (const span of recording.spans()) {
      for (const key of Object.keys(span.attributes)) {
        expect(FORBIDDEN_URL_ATTRS, `${key} is a whole-URL attribute`).not.toContain(key);
      }
    }
    // The callback span exists, with an outcome from the design's vocabulary.
    const callbackSpan = recording.spans().find((s) => s.name === SPAN_CONSENT_CALLBACK);
    expect(callbackSpan).toBeTruthy();
    expect(CONSENT_CALLBACK_OUTCOMES).toContain(callbackSpan?.attributes[ATTR_OUTCOME]);
  });
});

describe("the concurrent race", () => {
  it("two concurrent completions: exactly one saves; the loser conflicts and its sealed material is ledger-marked", async () => {
    const fixture = await seededReady("race");
    const a = await consult(fixture, prodIdentity);
    const b = await consult(fixture, prodIdentity);
    const codeA = (await authorizeAndRedirect(a.authorizeUrl)).code as string;
    const codeB = (await authorizeAndRedirect(b.authorizeUrl)).code as string;

    const [resA, resB] = await Promise.all([
      callback({ code: codeA, state: a.state }),
      callback({ code: codeB, state: b.state }),
    ]);
    const saved = [resA, resB].filter((r) => r.body.includes('"outcome":"connected"'));
    const conflicted = [resA, resB].filter((r) =>
      r.body.includes("Another connection attempt finished first — return to the app."),
    );
    expect(saved).toHaveLength(1);
    expect(conflicted).toHaveLength(1);
    // The conflict page posts error/conflict — the one explicit
    // pairing — to the recorded opener.
    expect(conflicted[0]!.body).toContain('"reason":"conflict"');
    expect(conflicted[0]!.body).toContain(`window.opener.postMessage(message, "${OPENER_ORIGIN}")`);
    expect(await t.prisma.userConnection.count({ where: { providerId: fixture.providerId } })).toBe(
      1,
    );

    // The loser's sealed material is ledger-marked in the same transaction as
    // the conflict write — the sweep retires it.
    const row = await t.prisma.userConnection.findFirstOrThrow({
      where: { providerId: fixture.providerId },
    });
    expect(row.pendingRetire).toBeTruthy();
    const envelope = ConnectionMaterialSchema.parse(JSON.parse(row.pendingRetire as string));
    const opened = createSecretStore({ devMasterKey: delegatedKek });
    // The marked material opens to a DIFFERENT token than the row's — it is
    // the loser's, retired-class, not the current material.
    const current = ConnectionMaterialSchema.parse(JSON.parse(row.material));
    expect(await opened.open(envelope.access)).not.toEqual(await opened.open(current.access));
    expect(await opened.open(envelope.refresh)).not.toEqual(await opened.open(current.refresh));
    expect(
      await t.prisma.auditEvent.count({
        where: { action: "connection.connected", appId: fixture.appId },
      }),
    ).toBe(1);
  });
});

describe("the failure pages — fixed strings, nothing saved", () => {
  it("the vendor declining renders the declined page with the provider's name", async () => {
    const fixture = await seededReady("declined");
    vendor.setModes({ authorizeMode: "deny" });
    const { authorizeUrl, state } = await consult(fixture, prodIdentity);
    const redirect = await authorizeAndRedirect(authorizeUrl);
    expect(redirect.error).toBe("access_denied");

    const res = await callback({ error: redirect.error as string, state });
    expect(res.status).toBe(200);
    expect(res.body).toContain(`You declined the connection at ${fixture.displayName}.`);
    expect(res.body).toContain('"outcome":"denied"');
    expect(res.body).not.toContain("access_denied");
    expect(await t.prisma.userConnection.count({ where: { providerId: fixture.providerId } })).toBe(
      0,
    );
  });

  it("a permissions-short grant renders the failed-permissions page", async () => {
    const fixture = await seededReady("short", { requestedScopes: ["read", "write"] });
    const { authorizeUrl, state } = await consult(fixture, prodIdentity);
    // The user granted fewer permissions than configured.
    const redirect = await authorizeAndRedirect(authorizeUrl, { scope: "read" });
    const res = await callback({ code: redirect.code as string, state });
    expect(res.status).toBe(200);
    expect(res.body).toContain(
      `${fixture.displayName} didn&#39;t grant all requested permissions — try again and approve them all.`,
    );
    expect(await t.prisma.userConnection.count({ where: { providerId: fixture.providerId } })).toBe(
      0,
    );
    // The gate's refusal sealed nothing — the delegated store took no write
    // (the exchange's binding invariant), so there is no material to retire either.
  });

  it("a hung vendor token endpoint renders the failed-service page", async () => {
    const fixture = await seededReady("hung");
    vendor.setModes({ tokenMode: "hang" });
    const { authorizeUrl, state } = await consult(fixture, prodIdentity);
    const redirect = await authorizeAndRedirect(authorizeUrl);
    const res = await callback({ code: redirect.code as string, state });
    expect(res.status).toBe(503);
    expect(res.body).toContain("Couldn&#39;t complete the connection — try again from the app.");
    expect(await t.prisma.userConnection.count({ where: { providerId: fixture.providerId } })).toBe(
      0,
    );
  }, 30_000);

  it("an unwired delegation renders the failed-service page (refuse, never degrade)", async () => {
    const fixture = await seededReady("unwired");
    const { authorizeUrl, state } = await consult(fixture, prodIdentity);
    const redirect = await authorizeAndRedirect(authorizeUrl);
    delete process.env.PORTAL_EGRESS_URL;
    try {
      const res = await callback({ code: redirect.code as string, state });
      expect(res.status).toBe(503);
      expect(res.body).toContain("Couldn&#39;t complete the connection — try again from the app.");
      expect(
        await t.prisma.userConnection.count({ where: { providerId: fixture.providerId } }),
      ).toBe(0);
    } finally {
      process.env.PORTAL_EGRESS_URL = egressBaseUrl;
    }
  });
});

describe("the disconnect landing mid-flight", () => {
  it("a disconnect between consult and completion renders the disconnected page and saves nothing", async () => {
    const fixture = await seededReady("disconnected");
    // Arrange: a dead (reconnect-needed) connection exists, so a fresh consult
    // starts an attempt; then the disconnect lands — the row invalidated and
    // the attempts killed, the one-UPDATE + kill pattern.
    await t.prisma.userConnection.create({
      data: {
        userOid,
        providerId: fixture.providerId,
        providerRevision: 1,
        env: "prod",
        status: "reconnect-needed",
        material: "seeded-dead-material",
        grantedScopes: ["read"],
        grantedAt: new Date(),
        expiresAt: new Date(Date.now() + 1000),
      },
    });
    const { authorizeUrl, state } = await consult(fixture, prodIdentity);
    await t.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`UPDATE user_connections
        SET status = 'invalidated', "pendingRetire" = "material", "updatedAt" = now()
        WHERE "userOid" = ${userOid} AND "providerId" = ${fixture.providerId}::uuid AND env = 'prod'`;
      await tx.connectionConsentAttempt.updateMany({
        where: { providerId: fixture.providerId, cancelledAt: null },
        data: { cancelledAt: new Date() },
      });
    });

    const redirect = await authorizeAndRedirect(authorizeUrl);
    const res = await callback({ code: redirect.code as string, state });
    expect(res.status).toBe(200);
    expect(res.body).toContain("This connection was disconnected.");
    expect(res.body).toContain('"outcome":"error"');
    // Nothing saved: the row stays invalidated, never resurrected.
    const row = await t.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid, providerId: fixture.providerId, env: "prod" },
      },
    });
    expect(row.status).toBe("invalidated");
    expect(row.material).toBe("seeded-dead-material");
    expect(
      await t.prisma.auditEvent.count({
        where: { action: "connection.connected", appId: fixture.appId },
      }),
    ).toBe(0);
  });

  it("a fresh consent over a dead row upserts — the CAS's replaceable half", async () => {
    const fixture = await seededReady("replace");
    await t.prisma.userConnection.create({
      data: {
        userOid,
        providerId: fixture.providerId,
        providerRevision: 1,
        env: "prod",
        status: "reconnect-needed",
        material: "seeded-dead-material",
        grantedScopes: ["read"],
        grantedAt: new Date(),
        expiresAt: new Date(Date.now() + 1000),
      },
    });
    const { authorizeUrl, state } = await consult(fixture, prodIdentity);
    const redirect = await authorizeAndRedirect(authorizeUrl);
    const res = await callback({ code: redirect.code as string, state });
    expect(res.status).toBe(200);
    expect(res.body).toContain('"outcome":"connected"');

    // The upsert replaced the dead row and ledger-marked ITS material for the
    // sweep in the same UPDATE (the reconnect-upsert rule).
    const row = await t.prisma.userConnection.findUniqueOrThrow({
      where: {
        userOid_providerId_env: { userOid, providerId: fixture.providerId, env: "prod" },
      },
    });
    expect(row.status).toBe("live");
    expect(row.material).not.toBe("seeded-dead-material");
    expect(row.pendingRetire).toBe("seeded-dead-material");
  });
});

describe("the telemetry contract (ADR-0037)", () => {
  it("counts callback outcomes on the consent counter, never identity", async () => {
    const fixture = await seededReady("counter");
    const { authorizeUrl, state } = await consult(fixture, prodIdentity);
    const redirect = await authorizeAndRedirect(authorizeUrl);
    await callback({ code: redirect.code as string, state });

    const metrics = await recording.metrics();
    const points = metrics.filter((m) => m.name === INSTR_CONSENT_OPERATIONS);
    expect(points.length).toBeGreaterThan(0);
    for (const point of points) {
      expect(Object.keys(point.attributes)).not.toContain("helix.userOid");
    }
    expect(
      points.some(
        (m) =>
          m.attributes["helix.consent.operation"] === "callback" &&
          m.attributes[ATTR_OUTCOME] === "connected",
      ),
    ).toBe(true);
  });
});
