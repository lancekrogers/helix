import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { LightMyRequestResponse } from "fastify";
import {
  EDGE_CLIENT_ID,
  findFixtureUser,
  pairwiseSub,
  startDevIdp,
  TestHttpSession,
  type RunningDevIdp,
} from "@azx-pbc/dev-idp";
import { buildApp } from "../app.js";
import { OpenIdConnectClient } from "./oidc.js";
import { PgSessionStore, hashSessionToken } from "./sessions.js";
import { FLOW_COOKIE, SESSION_COOKIE } from "./cookies.js";
import { publicOrigin } from "../config.js";
import {
  SPLIT_CONTROL_DOMAIN,
  splitEdgeConfig,
  testAuthConfig,
  testEdgeConfig,
} from "../test/config.js";
import { FakeBlobReader, FakeRegistry, registryEntry } from "../test/fakes.js";
import { TEST_DATABASE_URL, deleteApp, seedApp, type SeededApp } from "../test/seed.js";

/**
 * Appendix A end to end against the REAL pieces: oidc-provider (in-process,
 * ephemeral port) for discovery/PKCE/nonce/code exchange, and Postgres for
 * the pending-row → atomic-redeem lifecycle. The test plays the browser:
 * app.inject() for edge hops, fetch with a cookie jar for IdP hops.
 */

const REDIRECT_URI = "https://auth.local.helix.azxlabs.io:8080/callback";
const SPLIT_REDIRECT_URI = `https://auth.${SPLIT_CONTROL_DOMAIN}:8080/callback`;
const AUTH_HOST = { host: "auth.local.helix.azxlabs.io" };
const SPLIT_AUTH_HOST = { host: `auth.${SPLIT_CONTROL_DOMAIN}` };

let idp: RunningDevIdp;
let pool: Pool;
let sessions: PgSessionStore;
let oidc: OpenIdConnectClient;
let app: FastifyInstance;
let internalApp: SeededApp;
let groupApp: SeededApp;

function cookieValue(res: LightMyRequestResponse, name: string): string | undefined {
  const headers = res.headers["set-cookie"];
  const list = Array.isArray(headers) ? headers : headers ? [headers] : [];
  const line = list.find((l) => l.startsWith(`${name}=`));
  return line?.slice(name.length + 1).split(";", 1)[0] || undefined;
}

/** Drive the IdP (real HTTP) from the authorize URL to the edge callback URL. */
async function browseIdpLogin(
  authorizeUrl: string,
  userEmail: string,
  browser: TestHttpSession = new TestHttpSession(),
  redirectUri: string = REDIRECT_URI,
): Promise<URL> {
  const session = browser;
  let current = authorizeUrl;
  for (let hop = 0; hop < 12; hop++) {
    const res = await session.request(current);
    if (res.status >= 300 && res.status < 400) {
      const next = new URL(res.headers.get("location") ?? "/", current);
      await res.body?.cancel();
      if (next.toString().startsWith(redirectUri)) return next; // back to the edge
      current = next.toString();
      continue;
    }
    // The interaction picker — complete via the deterministic ?user= hook.
    await res.body?.cancel();
    if (!/\/interaction\//.test(current)) throw new Error(`stalled at ${current} (${res.status})`);
    const withUser = new URL(current);
    withUser.searchParams.set("user", userEmail);
    current = withUser.toString();
  }
  throw new Error("IdP login did not return to the edge");
}

/** Full login; returns the redeemed session cookie value and the complete URL. */
async function loginAs(
  userEmail: string,
  slug: string,
  rd = "/page",
  browser: TestHttpSession = new TestHttpSession(),
  opts: {
    targetApp?: FastifyInstance;
    authHost?: { host: string };
    redirectUri?: string;
  } = {},
): Promise<{
  callbackRes: LightMyRequestResponse;
  completeUrl?: URL;
  redeemRes?: LightMyRequestResponse;
  sessionCookie?: string;
}> {
  const edgeApp = opts.targetApp ?? app;
  const authHost = opts.authHost ?? AUTH_HOST;
  const redirectUri = opts.redirectUri ?? REDIRECT_URI;
  const start = await edgeApp.inject({
    url: `/start?app=${slug}&rd=${encodeURIComponent(rd)}`,
    headers: authHost,
  });
  expect(start.statusCode).toBe(302);
  const flowCookie = cookieValue(start, FLOW_COOKIE);

  const callbackUrl = await browseIdpLogin(
    start.headers.location as string,
    userEmail,
    browser,
    redirectUri,
  );
  const callbackRes = await edgeApp.inject({
    url: callbackUrl.pathname + callbackUrl.search,
    headers: { ...authHost, cookie: `${FLOW_COOKIE}=${flowCookie}` },
  });
  if (callbackRes.statusCode !== 302) return { callbackRes };

  const completeUrl = new URL(callbackRes.headers.location as string);
  const redeemRes = await edgeApp.inject({
    url: completeUrl.pathname + completeUrl.search,
    headers: { host: completeUrl.host },
  });
  return {
    callbackRes,
    completeUrl,
    redeemRes,
    sessionCookie: cookieValue(redeemRes, SESSION_COOKIE),
  };
}

beforeAll(async () => {
  idp = await startDevIdp({ edgeRedirectUris: [REDIRECT_URI, SPLIT_REDIRECT_URI] });
  pool = new Pool({ connectionString: TEST_DATABASE_URL, max: 4 });
  internalApp = await seedApp(pool, { live: true });
  groupApp = await seedApp(pool, {
    live: true,
    visibilityMode: "group",
    visibilityGroupIds: ["eng-team"],
  });

  const auth = testAuthConfig({
    issuerUrl: idp.issuer,
    clientId: "helix-edge",
    credential: { kind: "secret", clientSecret: "edge-dev-secret" },
    allowInsecureIdp: true,
  });
  sessions = new PgSessionStore(TEST_DATABASE_URL, { max: 4 });
  oidc = new OpenIdConnectClient(auth, REDIRECT_URI, { info: () => {}, warn: () => {} });
  await oidc.start();
  expect(oidc.isReady()).toBe(true);

  const registry = new FakeRegistry([
    registryEntry({
      appId: internalApp.appId,
      slug: internalApp.slug,
      blobPrefix: internalApp.blobPrefix,
    }),
    registryEntry({
      appId: groupApp.appId,
      slug: groupApp.slug,
      blobPrefix: groupApp.blobPrefix,
      visibilityMode: "group",
      visibilityGroupIds: ["eng-team"],
    }),
  ]);
  const blob = new FakeBlobReader();
  blob.set(`${internalApp.blobPrefix}index.html`, {
    body: "<body>internal app</body>",
    contentType: "text/html",
  });
  app = buildApp({
    // The gate is live: assets and /_api/me require the session minted above.
    config: testEdgeConfig({ auth, allowUnauthenticated: false }),
    registry,
    blob,
    sessions,
    oidc,
  });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  oidc.stop();
  await sessions.close();
  await deleteApp(pool, internalApp.appId);
  await deleteApp(pool, groupApp.appId);
  await pool.end();
  await idp.close();
});

describe("the full Appendix A flow against real oidc-provider + Postgres", () => {
  it("logs alice into an internal app and lands on rd", async () => {
    const { redeemRes, sessionCookie, completeUrl } = await loginAs(
      "alice@azx.dev",
      internalApp.slug,
      "/deep/link?q=1",
    );
    expect(redeemRes?.statusCode).toBe(302);
    expect(redeemRes?.headers.location).toBe("/deep/link?q=1");
    expect(completeUrl?.host).toBe(`${internalApp.slug}.local.helix.azxlabs.io:8080`);
    expect(sessionCookie).toBeTruthy();

    // The session row is real: alice's identity + group snapshot, app-scoped.
    // The oid is the directory object id — the invariant ADR-0048 exists for:
    // what the edge stores must be what the portal will store as ownerId for
    // the same login (pinned from the portal side in its own integration
    // suite, against this same fixture constant).
    const alice = findFixtureUser("alice@azx.dev")!;
    const session = await sessions.lookup(
      hashSessionToken(sessionCookie as string),
      internalApp.appId,
    );
    expect(session?.user.oid).toBe(alice.oid);
    expect(session?.user.displayName).toBe("Alice Anders");
    expect(session?.user.groups).toEqual(["eng-team", "platform-admin"]);
    expect(
      await sessions.lookup(hashSessionToken(sessionCookie as string), groupApp.appId),
    ).toBeNull();
  });

  it("admits bob (in eng-team) to the group app, and refuses mallory", async () => {
    const bob = await loginAs("bob@azx.dev", groupApp.slug);
    expect(bob.redeemRes?.statusCode).toBe(302);
    expect(bob.sessionCookie).toBeTruthy();

    const mallory = await loginAs("mallory@azx.dev", groupApp.slug);
    expect(mallory.callbackRes.statusCode).toBe(403);
    expect(mallory.completeUrl).toBeUndefined();
  });

  it("rejects a handoff replay (the atomic burn, on real Postgres)", async () => {
    const { completeUrl, redeemRes } = await loginAs("alice@azx.dev", internalApp.slug);
    expect(redeemRes?.statusCode).toBe(302);
    const replay = await app.inject({
      url: (completeUrl as URL).pathname + (completeUrl as URL).search,
      headers: { host: (completeUrl as URL).host },
    });
    expect(replay.statusCode).toBe(403);
    expect(replay.headers["set-cookie"]).toBeUndefined();
  });

  it("rejects an authorization-code replay at the real token endpoint", async () => {
    const start = await app.inject({
      url: `/start?app=${internalApp.slug}&rd=/`,
      headers: AUTH_HOST,
    });
    const flowCookie = cookieValue(start, FLOW_COOKIE);
    const callbackUrl = await browseIdpLogin(start.headers.location as string, "alice@azx.dev");

    const first = await app.inject({
      url: callbackUrl.pathname + callbackUrl.search,
      headers: { ...AUTH_HOST, cookie: `${FLOW_COOKIE}=${flowCookie}` },
    });
    expect(first.statusCode).toBe(302);

    // Same code, fresh flow? No — same flow cookie too: the IdP must refuse
    // the second exchange (single-use codes), so no second handoff exists.
    const second = await app.inject({
      url: callbackUrl.pathname + callbackUrl.search,
      headers: { ...AUTH_HOST, cookie: `${FLOW_COOKIE}=${flowCookie}` },
    });
    expect(second.statusCode).toBe(400);
  });

  it("serves gated assets and /_api/me with the minted session", async () => {
    const host = { host: `${internalApp.slug}.local.helix.azxlabs.io` };
    // Before login: navigation → login redirect; fetch → 401.
    const anon = await app.inject({ url: "/", headers: { ...host, "sec-fetch-mode": "navigate" } });
    expect(anon.statusCode).toBe(302);
    expect(anon.headers.location).toContain("https://auth.local.helix.azxlabs.io:8080/start");

    const { sessionCookie } = await loginAs("alice@azx.dev", internalApp.slug);
    const cookie = `${SESSION_COOKIE}=${sessionCookie}`;

    const page = await app.inject({ url: "/", headers: { ...host, cookie } });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain("internal app");

    const me = await app.inject({ url: "/_api/me", headers: { ...host, cookie } });
    expect(me.statusCode).toBe(200);
    const alice = findFixtureUser("alice@azx.dev")!;
    const meBody = me.json();
    expect(meBody).toEqual({
      user: {
        id: alice.oid,
        displayName: "Alice Anders",
        email: "alice@azx.dev",
      },
    });
    // The honesty half of the same invariant: the edge client's pairwise sub
    // is NOT the id apps see — dev-idp issues per-client subs like real Entra
    // (ADR-0048 decision 7), and this is the assertion that can never pass by
    // reading the wrong claim.
    expect((meBody as { user: { id: string } }).user.id).not.toBe(
      pairwiseSub(EDGE_CLIENT_ID, alice),
    );

    // Assert the KEY SET, not just the fields we expect: `toEqual` above would
    // still pass if a future edit widened MeResponseSchema, and the projection
    // that keeps the group snapshot out of an untrusted app's hands is the
    // `MeResponseSchema.parse` in appHost.ts — a "simplification" that sent the
    // session object directly would silently remove it. The address is
    // deliberately here (see packages/shared/src/auth.ts); `groups` is the thing
    // this guards.
    const body = me.json() as { user: Record<string, unknown> };
    expect(Object.keys(body.user).sort()).toEqual(["displayName", "email", "id"]);
  });

  it("silently refreshes a due session via prompt=none on the live IdP", async () => {
    // One browser for both round-trips — the IdP session cookie is what makes
    // prompt=none succeed without an interaction.
    const browser = new TestHttpSession();
    const { sessionCookie } = await loginAs("alice@azx.dev", internalApp.slug, "/page", browser);
    const host = { host: `${internalApp.slug}.local.helix.azxlabs.io` };

    // Make the session refresh-due, then navigate: the gate detours to
    // /start?silent=1.
    await pool.query(
      `UPDATE sessions SET "refreshDueAt" = now() - interval '1 minute' WHERE "tokenHash" = $1`,
      [hashSessionToken(sessionCookie as string)],
    );
    const nav = await app.inject({
      url: "/page",
      headers: {
        ...host,
        "sec-fetch-mode": "navigate",
        cookie: `${SESSION_COOKIE}=${sessionCookie}`,
      },
    });
    expect(nav.statusCode).toBe(302);
    const startUrl = new URL(nav.headers.location as string);
    expect(startUrl.searchParams.get("silent")).toBe("1");

    // Follow the detour: /start mints a prompt=none authorize URL…
    const start = await app.inject({
      url: startUrl.pathname + startUrl.search,
      headers: AUTH_HOST,
    });
    expect(start.statusCode).toBe(302);
    const authorizeUrl = new URL(start.headers.location as string);
    expect(authorizeUrl.searchParams.get("prompt")).toBe("none");
    const flowCookie = cookieValue(start, FLOW_COOKIE);

    // …which the IdP satisfies with NO interaction (same browser jar).
    const res = await browser.request(authorizeUrl.toString());
    expect([302, 303]).toContain(res.status);
    let next = new URL(res.headers.get("location") ?? "/", authorizeUrl);
    await res.body?.cancel();
    while (!next.toString().startsWith(REDIRECT_URI)) {
      const hop = await browser.request(next.toString());
      expect(hop.status, `unexpected interaction at ${next}`).toBeGreaterThanOrEqual(300);
      expect(hop.status).toBeLessThan(400);
      next = new URL(hop.headers.get("location") ?? "/", next);
      await hop.body?.cancel();
    }

    // The callback completes into a fresh session with a fresh snapshot.
    const callbackRes = await app.inject({
      url: next.pathname + next.search,
      headers: { ...AUTH_HOST, cookie: `${FLOW_COOKIE}=${flowCookie}` },
    });
    expect(callbackRes.statusCode).toBe(302);
    const completeUrl = new URL(callbackRes.headers.location as string);
    const redeemRes = await app.inject({
      url: completeUrl.pathname + completeUrl.search,
      headers: { host: completeUrl.host },
    });
    expect(redeemRes.statusCode).toBe(302);
    expect(redeemRes.headers.location).toBe("/page");
    const fresh = cookieValue(redeemRes, SESSION_COOKIE);
    expect(fresh).toBeTruthy();
    expect(fresh).not.toBe(sessionCookie);

    const session = await sessions.lookup(hashSessionToken(fresh as string), internalApp.appId);
    expect(session?.user.groups).toEqual(["eng-team", "platform-admin"]);
    expect(session?.refreshDueAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("rejects a callback whose state was swapped (real state validation)", async () => {
    const start = await app.inject({
      url: `/start?app=${internalApp.slug}&rd=/`,
      headers: AUTH_HOST,
    });
    const flowCookie = cookieValue(start, FLOW_COOKIE);
    const callbackUrl = await browseIdpLogin(start.headers.location as string, "alice@azx.dev");
    callbackUrl.searchParams.set("state", "swapped-by-attacker");

    const res = await app.inject({
      url: callbackUrl.pathname + callbackUrl.search,
      headers: { ...AUTH_HOST, cookie: `${FLOW_COOKIE}=${flowCookie}` },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe("a token without an oid claim refuses the login (ADR-0048 decision 2)", () => {
  // A second, deliberately misconfigured issuer: dev-idp's omitOidClaim mode
  // mints real tokens (real signature, real PKCE, real nonce) that simply
  // lack the canonical principal id. The refusal under test is the edge's,
  // not the issuer's — Entra cannot produce this token, which is exactly why
  // absence is treated as misconfiguration and fails closed.
  let bareIdp: RunningDevIdp;
  let bareApp: FastifyInstance;
  let bareOidc: OpenIdConnectClient;
  let bareSessions: PgSessionStore;
  const warnings: Array<{ obj: Record<string, unknown>; msg: string }> = [];

  beforeAll(async () => {
    bareIdp = await startDevIdp({ edgeRedirectUris: [REDIRECT_URI], omitOidClaim: true });
    const auth = testAuthConfig({
      issuerUrl: bareIdp.issuer,
      clientId: "helix-edge",
      credential: { kind: "secret", clientSecret: "edge-dev-secret" },
      allowInsecureIdp: true,
    });
    bareSessions = new PgSessionStore(TEST_DATABASE_URL, { max: 2 });
    bareOidc = new OpenIdConnectClient(auth, REDIRECT_URI, {
      info: () => {},
      warn: (obj, msg) => warnings.push({ obj: obj as Record<string, unknown>, msg }),
    });
    await bareOidc.start();

    const registry = new FakeRegistry([
      registryEntry({
        appId: internalApp.appId,
        slug: internalApp.slug,
        blobPrefix: internalApp.blobPrefix,
      }),
    ]);
    const blob = new FakeBlobReader();
    blob.set(`${internalApp.blobPrefix}index.html`, {
      body: "<body>internal app</body>",
      contentType: "text/html",
    });
    bareApp = buildApp({
      config: testEdgeConfig({ auth, allowUnauthenticated: false }),
      registry,
      blob,
      sessions: bareSessions,
      oidc: bareOidc,
    });
    await bareApp.ready();
  });

  afterAll(async () => {
    await bareApp.close();
    bareOidc.stop();
    await bareSessions.close();
    await bareIdp.close();
  });

  it("fails closed at the callback — 400 page, no session row, one specific log line", async () => {
    const start = await bareApp.inject({
      url: `/start?app=${internalApp.slug}&rd=/`,
      headers: AUTH_HOST,
    });
    expect(start.statusCode).toBe(302);
    const flowCookie = cookieValue(start, FLOW_COOKIE);
    const callbackUrl = await browseIdpLogin(start.headers.location as string, "alice@azx.dev");

    const callbackRes = await bareApp.inject({
      url: callbackUrl.pathname + callbackUrl.search,
      headers: { ...AUTH_HOST, cookie: `${FLOW_COOKIE}=${flowCookie}` },
    });
    // The same opaque-failure page every invalid exchange renders…
    expect(callbackRes.statusCode).toBe(400);
    expect(String(callbackRes.body)).toContain("Sign-in could not be completed");
    // …no handoff was minted, so there is nothing to redeem and no session
    // cookie. (The flow cookie IS cleared — that happens before the exchange,
    // on every failure, and is correct.)
    expect(callbackRes.headers.location).toBeUndefined();
    const setCookies = callbackRes.headers["set-cookie"];
    const cookieLines = Array.isArray(setCookies) ? setCookies : setCookies ? [setCookies] : [];
    expect(cookieLines.some((l) => l.startsWith(`${SESSION_COOKIE}=`))).toBe(false);

    // …and the operator is told the real cause: a stable-event line, not the
    // generic code-exchange failure (same diagnosability posture as the
    // group-overage line). This is the line an alert would key on.
    const missingOid = warnings.find((w) => w.obj.event === "auth.oidc_missing_principal");
    expect(
      missingOid,
      `expected auth.oidc_missing_principal among: ${JSON.stringify(warnings)}`,
    ).toBeTruthy();
    expect(missingOid?.obj.sub).toBe(
      pairwiseSub(EDGE_CLIENT_ID, findFixtureUser("alice@azx.dev")!),
    );
    // The refusal is the only complaint — no code_exchange_failed noise on top.
    expect(warnings.filter((w) => w.obj.event === "auth.code_exchange_failed")).toHaveLength(0);
  });
});

describe("split layout against real oidc-provider + Postgres", () => {
  let splitApp: FastifyInstance;
  let splitOidc: OpenIdConnectClient;

  beforeAll(async () => {
    const auth = testAuthConfig({
      issuerUrl: idp.issuer,
      clientId: "helix-edge",
      credential: { kind: "secret", clientSecret: "edge-dev-secret" },
      allowInsecureIdp: true,
    });
    splitOidc = new OpenIdConnectClient(auth, SPLIT_REDIRECT_URI, {
      info: () => {},
      warn: () => {},
    });
    await splitOidc.start();
    const cfg = splitEdgeConfig({ auth, allowUnauthenticated: false });
    splitApp = buildApp({
      config: cfg,
      registry: new FakeRegistry([
        registryEntry({
          appId: internalApp.appId,
          slug: internalApp.slug,
          blobPrefix: internalApp.blobPrefix,
        }),
      ]),
      blob: new FakeBlobReader(),
      sessions,
      oidc: splitOidc,
    });
    await splitApp.ready();
  });

  afterAll(async () => {
    await splitApp.close();
    splitOidc.stop();
  });

  it("logs in through control auth and lands on the apps host", async () => {
    const cfg = splitEdgeConfig({ auth: testAuthConfig(), allowUnauthenticated: false });
    const { redeemRes, completeUrl } = await loginAs(
      "alice@azx.dev",
      internalApp.slug,
      "/page",
      new TestHttpSession(),
      { targetApp: splitApp, authHost: SPLIT_AUTH_HOST, redirectUri: SPLIT_REDIRECT_URI },
    );
    expect(redeemRes?.statusCode).toBe(302);
    expect(completeUrl?.origin).toBe(publicOrigin(cfg, internalApp.slug));
  });

  it("silently refreshes via prompt=none on the control auth host", async () => {
    const browser = new TestHttpSession();
    const appsHost = { host: `${internalApp.slug}.${splitEdgeConfig().baseDomain}` };
    const { sessionCookie } = await loginAs("alice@azx.dev", internalApp.slug, "/page", browser, {
      targetApp: splitApp,
      authHost: SPLIT_AUTH_HOST,
      redirectUri: SPLIT_REDIRECT_URI,
    });

    await pool.query(
      `UPDATE sessions SET "refreshDueAt" = now() - interval '1 minute' WHERE "tokenHash" = $1`,
      [hashSessionToken(sessionCookie as string)],
    );
    const nav = await splitApp.inject({
      url: "/page",
      headers: {
        ...appsHost,
        "sec-fetch-mode": "navigate",
        cookie: `${SESSION_COOKIE}=${sessionCookie}`,
      },
    });
    expect(nav.statusCode).toBe(302);
    const startUrl = new URL(nav.headers.location as string);
    expect(startUrl.host).toBe(`${SPLIT_AUTH_HOST.host}:8080`);
    expect(startUrl.searchParams.get("silent")).toBe("1");

    const start = await splitApp.inject({
      url: startUrl.pathname + startUrl.search,
      headers: SPLIT_AUTH_HOST,
    });
    expect(start.statusCode).toBe(302);
    const authorizeUrl = new URL(start.headers.location as string);
    expect(authorizeUrl.searchParams.get("prompt")).toBe("none");
    const flowCookie = cookieValue(start, FLOW_COOKIE);

    const res = await browser.request(authorizeUrl.toString());
    expect([302, 303]).toContain(res.status);
    let next = new URL(res.headers.get("location") ?? "/", authorizeUrl);
    await res.body?.cancel();
    while (!next.toString().startsWith(SPLIT_REDIRECT_URI)) {
      const hop = await browser.request(next.toString());
      expect(hop.status, `unexpected interaction at ${next}`).toBeGreaterThanOrEqual(300);
      expect(hop.status).toBeLessThan(400);
      next = new URL(hop.headers.get("location") ?? "/", next);
      await hop.body?.cancel();
    }

    const callbackRes = await splitApp.inject({
      url: next.pathname + next.search,
      headers: { ...SPLIT_AUTH_HOST, cookie: `${FLOW_COOKIE}=${flowCookie}` },
    });
    expect(callbackRes.statusCode).toBe(302);
    const completeUrl = new URL(callbackRes.headers.location as string);
    expect(completeUrl.origin).toBe(publicOrigin(splitEdgeConfig(), internalApp.slug));
    const redeemRes = await splitApp.inject({
      url: completeUrl.pathname + completeUrl.search,
      headers: { host: completeUrl.host },
    });
    expect(redeemRes.statusCode).toBe(302);
    expect(redeemRes.headers.location).toBe("/page");
    const fresh = cookieValue(redeemRes, SESSION_COOKIE);
    expect(fresh).toBeTruthy();
    expect(fresh).not.toBe(sessionCookie);
  });

  it("concurrent redeem allows exactly one session cookie", async () => {
    const browser = new TestHttpSession();
    const start = await splitApp.inject({
      url: `/start?app=${internalApp.slug}&rd=${encodeURIComponent("/page")}`,
      headers: SPLIT_AUTH_HOST,
    });
    const flowCookie = cookieValue(start, FLOW_COOKIE);
    const callbackUrl = await browseIdpLogin(
      start.headers.location as string,
      "alice@azx.dev",
      browser,
      SPLIT_REDIRECT_URI,
    );
    const callbackRes = await splitApp.inject({
      url: callbackUrl.pathname + callbackUrl.search,
      headers: { ...SPLIT_AUTH_HOST, cookie: `${FLOW_COOKIE}=${flowCookie}` },
    });
    const completeUrl = new URL(callbackRes.headers.location as string);
    const url = completeUrl!.pathname + completeUrl!.search;
    const host = { host: completeUrl!.host };
    const results = await Promise.all(
      Array.from({ length: 8 }, () => splitApp.inject({ url, headers: host })),
    );
    const winners = results.filter((r) => cookieValue(r, SESSION_COOKIE));
    expect(winners).toHaveLength(1);
    for (const r of results) {
      if (!cookieValue(r, SESSION_COOKIE)) {
        expect(r.statusCode).toBe(403);
      }
    }
  });
});
