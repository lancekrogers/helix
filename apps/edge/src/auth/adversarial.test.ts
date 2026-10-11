import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { LightMyRequestResponse } from "fastify";
import { AuthorizationResponseError } from "openid-client";
import { redactUrl } from "@azx-pbc/shared/logging";
import { buildApp } from "../app.js";
import { summarizeExchangeError } from "./oidc.js";
import { deriveAuthKeys } from "./secrets.js";
import { mintHandoffToken } from "./handoff.js";
import { hashSessionToken, newSessionToken } from "./sessions.js";
import { FLOW_COOKIE, SESSION_COOKIE } from "./cookies.js";
import { mintFlowToken } from "./flow.js";
import { controlOrigin, publicOrigin } from "../config.js";
import {
  SPLIT_APPS_DOMAIN,
  SPLIT_CONTROL_DOMAIN,
  splitEdgeConfig,
  testAuthConfig,
  testEdgeConfig,
  TEST_AUTH_SECRET,
} from "../test/config.js";
import {
  FakeBlobReader,
  FakeLlmProvider,
  FakeOidcClient,
  FakeRegistry,
  FakeSessionStore,
  FakeUsageStore,
  registryEntry,
} from "../test/fakes.js";

/**
 * The adversarial suite for the handoff path (project plan §4 M3, §6:
 * adversarial tests land WITH the auth code). Each block names the attack it
 * kills. Unit-level — fakes for IdP and store; the concurrency race and the
 * real-IdP flow live in the integration suites.
 */

const APP_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const APP_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const KEYS = deriveAuthKeys(TEST_AUTH_SECRET);

const LAYOUTS = [
  {
    name: "single",
    config: testEdgeConfig,
    control: "local.helix.azxlabs.io",
    apps: "local.helix.azxlabs.io",
  },
  {
    name: "split",
    config: splitEdgeConfig,
    control: SPLIT_CONTROL_DOMAIN,
    apps: SPLIT_APPS_DOMAIN,
  },
] as const;
type Layout = (typeof LAYOUTS)[number];

interface AuthEdge {
  app: FastifyInstance;
  sessions: FakeSessionStore;
  oidc: FakeOidcClient;
  registry: FakeRegistry;
  layout: Layout;
  authHost: { host: string };
  controlHost: string;
  appHost(slug: string): string;
}

function authHostHeader(layout: Layout): { host: string } {
  const cfg = layout.config({ auth: testAuthConfig() });
  const origin = controlOrigin(cfg, "auth");
  return { host: new URL(origin).host };
}

function appHostHeader(layout: Layout, slug: string): { host: string } {
  const cfg = layout.config({ auth: testAuthConfig() });
  const origin = publicOrigin(cfg, slug);
  return { host: new URL(origin).host };
}

function buildAuthEdge(layout: Layout = LAYOUTS[0]): AuthEdge {
  const registry = new FakeRegistry([
    registryEntry({ appId: APP_A, slug: "appa", blobPrefix: "apps/a/1/" }),
    registryEntry({ appId: APP_B, slug: "appb", blobPrefix: "apps/b/1/" }),
    registryEntry({
      appId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      slug: "team",
      blobPrefix: "apps/c/1/",
      visibilityMode: "group",
      visibilityGroupIds: ["eng-team"],
    }),
    registryEntry({
      appId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
      slug: "gated",
      visibilityMode: "password",
    }),
    registryEntry({
      appId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
      slug: "open",
      visibilityMode: "public",
    }),
  ]);
  const sessions = new FakeSessionStore();
  const oidc = new FakeOidcClient();
  const cfg = layout.config({ auth: testAuthConfig() });
  const app = buildApp({
    config: cfg,
    registry,
    blob: new FakeBlobReader(),
    sessions,
    oidc,
  });
  const controlHost = new URL(controlOrigin(cfg, "auth")).host;
  return {
    app,
    sessions,
    oidc,
    registry,
    layout,
    authHost: authHostHeader(layout),
    controlHost,
    appHost: (slug: string) => appHostHeader(layout, slug).host,
  };
}

function cookieValue(res: LightMyRequestResponse, name: string): string | undefined {
  const headers = res.headers["set-cookie"];
  const list = Array.isArray(headers) ? headers : headers ? [headers] : [];
  for (const line of list) {
    if (line.startsWith(`${name}=`)) {
      const value = line.slice(name.length + 1).split(";", 1)[0];
      if (value) return value;
    }
  }
  return undefined;
}

/** Steps 1–7 of Appendix A against the fakes; returns the handoff redirect. */
async function login(
  edge: AuthEdge,
  opts: { slug?: string; rd?: string; silent?: boolean } = {},
): Promise<{
  completeUrl: URL;
  flowCookie: string;
  state: string;
  callbackRes: LightMyRequestResponse;
}> {
  const slug = opts.slug ?? "appa";
  const start = await edge.app.inject({
    url: `/start?app=${slug}&rd=${encodeURIComponent(opts.rd ?? "/page")}${opts.silent ? "&silent=1" : ""}`,
    headers: edge.authHost,
  });
  expect(start.statusCode).toBe(302);
  const flowCookie = cookieValue(start, FLOW_COOKIE);
  expect(flowCookie).toBeTruthy();
  const state = new URL(start.headers.location as string).searchParams.get("state");
  expect(state).toBeTruthy();

  const callback = await edge.app.inject({
    url: `/callback?code=good&state=${state}`,
    headers: { ...edge.authHost, cookie: `${FLOW_COOKIE}=${flowCookie}` },
  });
  expect(callback.statusCode).toBe(302);
  return {
    completeUrl: new URL(callback.headers.location as string),
    flowCookie: flowCookie as string,
    state: state as string,
    callbackRes: callback,
  };
}

async function redeem(
  edge: AuthEdge,
  completeUrl: URL,
  opts: { host?: string; cookie?: string } = {},
): Promise<LightMyRequestResponse> {
  return edge.app.inject({
    url: completeUrl.pathname + completeUrl.search,
    headers: {
      host: opts.host ?? completeUrl.host,
      ...(opts.cookie ? { cookie: opts.cookie } : {}),
    },
  });
}

describe.each(LAYOUTS)("$name layout", (layout) => {
  describe("the happy path (everything the attacks try to subvert)", () => {
    it("start → callback → complete mints a host-scoped session", async () => {
      const edge = buildAuthEdge(layout);
      const { completeUrl } = await login(edge, { rd: "/deep/link?q=1" });

      expect(completeUrl.host).toBe(edge.appHost("appa"));
      expect(completeUrl.protocol).toBe("https:");
      expect(completeUrl.pathname).toBe("/_auth/complete");

      const res = await redeem(edge, completeUrl);
      expect(res.statusCode).toBe(302);
      expect(res.headers.location).toBe("/deep/link?q=1");
      expect(res.headers["cache-control"]).toBe("no-store");
      expect(res.headers["referrer-policy"]).toBe("no-referrer");

      const session = cookieValue(res, SESSION_COOKIE);
      expect(session).toBeTruthy();
      // The cookie is never the URL-borne token.
      expect(completeUrl.searchParams.get("token")).not.toBe(session);
      // And the store sees only its hash, bound to the right app.
      expect(await edge.sessions.lookup(hashSessionToken(session as string), APP_A)).not.toBeNull();

      const setCookie = String(res.headers["set-cookie"]);
      for (const attr of ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"]) {
        expect(setCookie).toContain(attr);
      }
      expect(setCookie).not.toContain("Domain");
    });

    it("the /start redirect is no-store and never leaks app/rd via Referer", async () => {
      const edge = buildAuthEdge(layout);
      const start = await edge.app.inject({
        url: "/start?app=appa&rd=/page",
        headers: edge.authHost,
      });
      expect(start.statusCode).toBe(302);
      expect(start.headers["cache-control"]).toBe("no-store");
      expect(start.headers["referrer-policy"]).toBe("no-referrer");
    });

    it("the token-bearing callback redirect is no-store, no-referrer, and log-redacted", async () => {
      const edge = buildAuthEdge(layout);
      const start = await edge.app.inject({
        url: "/start?app=appa&rd=/page",
        headers: edge.authHost,
      });
      const flowCookie = cookieValue(start, FLOW_COOKIE);
      const state = new URL(start.headers.location as string).searchParams.get("state");

      const callback = await edge.app.inject({
        url: `/callback?code=good&state=${state}`,
        headers: { ...edge.authHost, cookie: `${FLOW_COOKIE}=${flowCookie}` },
      });
      expect(callback.statusCode).toBe(302);
      // The Location carries a live handoff token — no caches, no referrers...
      expect(callback.headers["cache-control"]).toBe("no-store");
      expect(callback.headers["referrer-policy"]).toBe("no-referrer");

      // ...and no access logs, on either leg of the redirect (issue #20).
      const completeUrl = new URL(callback.headers.location as string);
      const handoff = completeUrl.searchParams.get("token") as string;
      expect(handoff).toBeTruthy();
      expect(redactUrl(`/callback?code=good&state=${state}`)).toBe(
        `/callback?code=REDACTED&state=REDACTED`,
      );
      expect(redactUrl(completeUrl.pathname + completeUrl.search)).toBe(
        "/_auth/complete?token=REDACTED",
      );
    });

    it("a failed exchange logs the OAuth code, not the text the caller chose", async () => {
      // Reachable with a valid flow cookie + state: `invalid_request` is not in
      // SILENT_LOGIN_ERRORS, and the callback hands the raw query to exchangeCode.
      // openid-client lifts `error_description` onto an own enumerable property,
      // and carries the whole response in `cause` — pino's stock `err` serializer
      // writes both verbatim (issue #20).
      const params = new URLSearchParams({
        error: "invalid_request",
        error_description: "SENTINEL_SECRET_abc123",
        state: "xyz",
      });
      const authError = new AuthorizationResponseError("authorization response error", {
        cause: params,
      });
      expect(authError.error_description).toBe("SENTINEL_SECRET_abc123");

      const logged = summarizeExchangeError(authError);
      expect(JSON.stringify(logged)).not.toContain("SENTINEL_SECRET_abc123");
      expect(logged).toEqual({
        errName: "AuthorizationResponseError",
        oauthError: "invalid_request",
      });

      // Anything that isn't an OAuth error keeps its stack: that text is ours.
      const ours = new Error("discovery has not completed");
      expect(summarizeExchangeError(ours)).toEqual({ err: ours });
    });

    it("silent=1 requests prompt=none from the IdP", async () => {
      const edge = buildAuthEdge(layout);
      await login(edge, { silent: true });
      expect(edge.oidc.authorizeRequests.at(-1)?.prompt).toBe("none");
    });

    it("a silent refresh the IdP cannot satisfy restarts interactively", async () => {
      const edge = buildAuthEdge(layout);
      const start = await edge.app.inject({
        url: "/start?app=appa&rd=/page&silent=1",
        headers: edge.authHost,
      });
      const flowCookie = cookieValue(start, FLOW_COOKIE);
      const state = new URL(start.headers.location as string).searchParams.get("state");

      const res = await edge.app.inject({
        url: `/callback?error=login_required&state=${state}`,
        headers: { ...edge.authHost, cookie: `${FLOW_COOKIE}=${flowCookie}` },
      });
      expect(res.statusCode).toBe(302);
      expect(res.headers["referrer-policy"]).toBe("no-referrer");
      const restart = new URL(res.headers.location as string);
      expect(restart.host).toBe(edge.controlHost);
      expect(restart.pathname).toBe("/start");
      expect(restart.searchParams.get("app")).toBe("appa");
      expect(restart.searchParams.get("rd")).toBe("/page");
      expect(restart.searchParams.get("silent")).toBeNull();
    });
  });

  describe("attack: handoff replay", () => {
    it("redeems exactly once; the second attempt gets 403 and no cookie", async () => {
      const edge = buildAuthEdge(layout);
      const { completeUrl } = await login(edge);

      const first = await redeem(edge, completeUrl);
      expect(first.statusCode).toBe(302);

      const second = await redeem(edge, completeUrl);
      expect(second.statusCode).toBe(403);
      expect(second.headers["set-cookie"]).toBeUndefined();
      expect(second.headers["cache-control"]).toBe("no-store");
    });
  });

  describe("attack: audience confusion", () => {
    it("a token captured by appB is worthless there (JWS aud check)", async () => {
      const edge = buildAuthEdge(layout);
      const { completeUrl } = await login(edge); // audience: appa
      const res = await redeem(edge, completeUrl, { host: edge.appHost("appb") });
      expect(res.statusCode).toBe(403);
      expect(res.headers["set-cookie"]).toBeUndefined();
      // And the pending session survives for the legitimate host.
      expect((await redeem(edge, completeUrl)).statusCode).toBe(302);
    });

    it("a JWS-valid token for appB cannot redeem appA's session row (row-level check)", async () => {
      const edge = buildAuthEdge(layout);
      const { completeUrl } = await login(edge); // pending row is appa's
      const sessionId = [...edge.sessions.byId.keys()][0] as string;

      // Hypothetical bug: a token re-minted for appB referencing appa's row.
      const crossToken = await mintHandoffToken(
        { sessionId, appId: APP_B, rd: "/" },
        KEYS.handoffKey,
        30,
      );
      const res = await edge.app.inject({
        url: `/_auth/complete?token=${crossToken}`,
        headers: { host: edge.appHost("appb") },
      });
      expect(res.statusCode).toBe(403);
      expect(res.headers["set-cookie"]).toBeUndefined();
      expect(completeUrl.searchParams.get("token")).not.toBe(crossToken);
    });
  });

  describe("attack: open redirect via /start", () => {
    it.each([
      "https://evil.example/",
      "http://evil.example/",
      "//evil.example/",
      "/\\evil.example",
      "\\evil.example",
      "page",
      "../up",
      "/a\rb",
    ])("rejects rd=%j with 400 and never contacts the IdP", async (rd) => {
      const edge = buildAuthEdge(layout);
      const res = await edge.app.inject({
        url: `/start?app=appa&rd=${encodeURIComponent(rd)}`,
        headers: edge.authHost,
      });
      expect(res.statusCode).toBe(400);
      expect(edge.oidc.authorizeRequests).toHaveLength(0);
      expect(res.headers["set-cookie"]).toBeUndefined();
    });

    it("404s unknown/archived apps, 503s public, but starts SSO for a password app", async () => {
      const edge = buildAuthEdge(layout);
      expect(
        (await edge.app.inject({ url: "/start?app=nope", headers: edge.authHost })).statusCode,
      ).toBe(404);
      expect((await edge.app.inject({ url: "/start", headers: edge.authHost })).statusCode).toBe(
        404,
      );
      // public has no session to mint.
      expect(
        (await edge.app.inject({ url: "/start?app=open", headers: edge.authHost })).statusCode,
      ).toBe(503);
      // password apps also admit SSO users, so /start proceeds (302 to the IdP).
      expect(
        (await edge.app.inject({ url: "/start?app=gated", headers: edge.authHost })).statusCode,
      ).toBe(302);
    });
  });

  describe("attack: state/nonce tampering at /callback", () => {
    it("rejects a state that does not match the flow cookie", async () => {
      const edge = buildAuthEdge(layout);
      const start = await edge.app.inject({ url: "/start?app=appa&rd=/", headers: edge.authHost });
      const flowCookie = cookieValue(start, FLOW_COOKIE);

      const res = await edge.app.inject({
        url: `/callback?code=good&state=attacker-chosen`,
        headers: { ...edge.authHost, cookie: `${FLOW_COOKIE}=${flowCookie}` },
      });
      expect(res.statusCode).toBe(400);
      expect(edge.sessions.byId.size).toBe(0); // no pending row, no handoff
    });

    it("rejects a callback with no flow cookie (forged or expired round-trip)", async () => {
      const edge = buildAuthEdge(layout);
      const res = await edge.app.inject({
        url: "/callback?code=good&state=x",
        headers: edge.authHost,
      });
      expect(res.statusCode).toBe(400);
      expect(edge.sessions.byId.size).toBe(0);
    });

    it("rejects a flow cookie signed with the wrong key", async () => {
      const edge = buildAuthEdge(layout);
      const foreignKeys = deriveAuthKeys(Buffer.from("ffffffffffffffffffffffffffffffff"));
      const forged = await mintFlowToken(
        { state: "s", nonce: "n", codeVerifier: "v", app: "appa", rd: "/", silent: false },
        foreignKeys.flowKey,
      );
      const res = await edge.app.inject({
        url: "/callback?code=good&state=s",
        headers: { ...edge.authHost, cookie: `${FLOW_COOKIE}=${forged}` },
      });
      expect(res.statusCode).toBe(400);
      expect(edge.sessions.byId.size).toBe(0);
    });

    it("an exchange failure (bad nonce/code — IdP-verified) mints nothing", async () => {
      const edge = buildAuthEdge(layout);
      edge.oidc.forcedOutcome = { kind: "invalid" };
      const start = await edge.app.inject({ url: "/start?app=appa&rd=/", headers: edge.authHost });
      const flowCookie = cookieValue(start, FLOW_COOKIE);
      const state = new URL(start.headers.location as string).searchParams.get("state");
      const res = await edge.app.inject({
        url: `/callback?code=good&state=${state}`,
        headers: { ...edge.authHost, cookie: `${FLOW_COOKIE}=${flowCookie}` },
      });
      expect(res.statusCode).toBe(400);
      expect(edge.sessions.byId.size).toBe(0);
    });
  });

  describe("attack: session fixation at /_auth/complete", () => {
    it("ignores attacker-preset session cookies; the minted value is fresh", async () => {
      const edge = buildAuthEdge(layout);
      const { completeUrl } = await login(edge);
      const res = await redeem(edge, completeUrl, {
        cookie: `${SESSION_COOKIE}=attacker-fixed-value`,
      });
      expect(res.statusCode).toBe(302);
      const minted = cookieValue(res, SESSION_COOKIE);
      expect(minted).toBeTruthy();
      expect(minted).not.toBe("attacker-fixed-value");
      // The attacker's value never becomes a session.
      expect(
        await edge.sessions.lookup(hashSessionToken("attacker-fixed-value"), APP_A),
      ).toBeNull();
    });
  });

  describe("attack: visibility bypass", () => {
    it("denies a group-mode app to a user outside the group, minting nothing", async () => {
      const edge = buildAuthEdge(layout);
      edge.oidc.identity = {
        oid: "oid-mallory",
        displayName: "Mallory",
        name: null,
        email: null,
        groups: [],
      };
      const start = await edge.app.inject({ url: "/start?app=team&rd=/", headers: edge.authHost });
      const flowCookie = cookieValue(start, FLOW_COOKIE);
      const state = new URL(start.headers.location as string).searchParams.get("state");
      const res = await edge.app.inject({
        url: `/callback?code=good&state=${state}`,
        headers: { ...edge.authHost, cookie: `${FLOW_COOKIE}=${flowCookie}` },
      });
      expect(res.statusCode).toBe(403);
      expect(edge.sessions.byId.size).toBe(0);
    });
  });

  describe("the two-router discipline for auth routes", () => {
    it("auth routes never answer on app or platform hosts", async () => {
      const edge = buildAuthEdge(layout);
      // /start on an app host is an asset path, not a login endpoint.
      const onApp = await edge.app.inject({
        url: "/start",
        headers: { host: edge.appHost("appa") },
      });
      expect(onApp.statusCode).toBe(404); // empty fake blob — but no redirect
      expect(onApp.headers.location).toBeUndefined();

      const onPlatform = await edge.app.inject({
        url: "/start?app=appa",
        headers: { host: layout.apps },
      });
      expect(onPlatform.statusCode).toBe(404);
    });

    it("/_auth/complete never answers on the auth or platform hosts", async () => {
      const edge = buildAuthEdge(layout);
      const { completeUrl } = await login(edge);
      const onAuth = await redeem(edge, completeUrl, { host: edge.controlHost });
      expect(onAuth.statusCode).toBe(404);
      const appsApex = new URL(publicOrigin(layout.config({ auth: testAuthConfig() }), null)).host;
      const onPlatform = await redeem(edge, completeUrl, { host: appsApex });
      expect(onPlatform.statusCode).toBe(404);
    });

    it("/_auth/* and /_api/* on app hosts never reach the blob store", async () => {
      const edge = buildAuthEdge(layout);
      const blob = new FakeBlobReader();
      const app = buildApp({
        config: layout.config(),
        registry: edge.registry,
        blob,
        sessions: edge.sessions,
        oidc: edge.oidc,
      });
      for (const url of ["/_auth/anything", "/_auth", "/_api/me", "/_api", "/_api/llm/v1"]) {
        const res = await app.inject({ url, headers: { host: edge.appHost("appa") } });
        expect(res.statusCode, url).toBe(404);
      }
      expect(blob.requests).toHaveLength(0);
      await app.close();
    });

    it("auth routes fail closed when the auth stack is not configured", async () => {
      const app = buildApp({
        config: layout.config(), // auth: null
        registry: new FakeRegistry([registryEntry({ slug: "appa", appId: APP_A })]),
        blob: new FakeBlobReader(),
      });
      const authHost = authHostHeader(layout);
      expect((await app.inject({ url: "/start?app=appa", headers: authHost })).statusCode).toBe(
        503,
      );
      expect((await app.inject({ url: "/callback", headers: authHost })).statusCode).toBe(503);
      const complete = await app.inject({
        url: "/_auth/complete?token=x",
        headers: { host: appHostHeader(layout, "appa").host },
      });
      expect(complete.statusCode).toBe(404);
      await app.close();
    });
  });

  /**
   * The M4 LLM gateway as an attack surface (project plan §4, §6 — adversarial
   * tests land with the code). Each block names what it kills. Provider + ledger
   * are fakes; the containment properties are real.
   */
  describe("attack: the /_api/llm/chat gateway", () => {
    const GRANT = { models: ["claude-opus-4-8"], dollarsPerDay: 1 };
    const ASK = { model: "claude-opus-4-8", messages: [{ role: "user", content: "hi" }] };

    interface GatewayEdge {
      app: FastifyInstance;
      sessions: FakeSessionStore;
      provider: FakeLlmProvider;
      usage: FakeUsageStore;
    }

    function buildGatewayEdge(forLayout: Layout = layout): GatewayEdge {
      const sessions = new FakeSessionStore();
      const provider = new FakeLlmProvider();
      const usage = new FakeUsageStore();
      const app = buildApp({
        config: forLayout.config({ auth: testAuthConfig(), allowUnauthenticated: false }),
        registry: new FakeRegistry([
          registryEntry({ appId: APP_A, slug: "appa", blobPrefix: "apps/a/1/", llm: GRANT }),
          registryEntry({ appId: APP_B, slug: "appb", blobPrefix: "apps/b/1/", llm: GRANT }),
        ]),
        blob: new FakeBlobReader(),
        sessions,
        oidc: new FakeOidcClient(),
        llmProvider: provider,
        usage,
      });
      return { app, sessions, provider, usage };
    }

    async function seed(sessions: FakeSessionStore, appId: string): Promise<string> {
      const id = randomUUID();
      await sessions.createPending({
        id,
        appId,
        user: {
          oid: "oid-alice",
          displayName: "Alice Anders",
          name: null,
          email: null,
          kind: "user",
          groups: [],
        },
        refreshDueAt: new Date(Date.now() + 60_000),
        expiresAt: new Date(Date.now() + 3_600_000),
      });
      const token = newSessionToken();
      await sessions.redeem(id, appId, hashSessionToken(token));
      return token;
    }

    function call(
      edge: GatewayEdge,
      token: string,
      opts: {
        host: string;
        origin?: string | null;
        /** Send the literal header value `null` (Fetch "opaque origin"), not omit Origin. */
        originLiteralNull?: boolean;
        secFetchSite?: string;
        secFetchMode?: string;
      },
    ): Promise<LightMyRequestResponse> {
      const hostHeader = opts.host.includes(":") ? opts.host : `${opts.host}:8080`;
      const origin = opts.originLiteralNull
        ? "null"
        : opts.origin === null
          ? undefined
          : (opts.origin ?? `https://${hostHeader}`);
      return edge.app.inject({
        method: "POST",
        url: "/_api/llm/chat",
        headers: {
          host: hostHeader,
          "sec-fetch-mode": opts.secFetchMode ?? "cors",
          "content-type": "application/json",
          ...(origin !== undefined ? { origin } : {}),
          ...(opts.secFetchSite ? { "sec-fetch-site": opts.secFetchSite } : {}),
          cookie: `${SESSION_COOKIE}=${token}`,
        },
        payload: ASK,
      });
    }

    function gwAppHost(slug: string): string {
      return appHostHeader(layout, slug).host;
    }

    it("kills a sibling-subdomain CSRF POST riding the session", async () => {
      const edge = buildGatewayEdge();
      const token = await seed(edge.sessions, APP_A);
      // appb tries to drive appa's gateway with appa's Origin spoof-attempt blocked
      // by the Origin check; here a real appa request from a sibling origin.
      const res = await call(edge, token, {
        host: gwAppHost("appa"),
        origin: `https://${gwAppHost("appb")}`,
      });
      expect(res.statusCode).toBe(403);
      expect(edge.provider.calls).toHaveLength(0);
    });

    it("a session minted for app A cannot spend app B's budget", async () => {
      const edge = buildGatewayEdge();
      const tokenA = await seed(edge.sessions, APP_A);
      // Same cookie, app B host + app B origin: the gate looks the row up scoped
      // to app B's id and finds nothing → 401, never attributed to app B.
      const res = await call(edge, tokenA, { host: gwAppHost("appb") });
      expect(res.statusCode).toBe(401);
      expect(edge.provider.calls).toHaveLength(0);
      expect(edge.usage.records).toHaveLength(0);
    });

    it("blocks a budget-exhausted app and audits the block", async () => {
      const edge = buildGatewayEdge();
      edge.usage.spendTodayMicro = 1_000_000;
      const token = await seed(edge.sessions, APP_A);
      const res = await call(edge, token, { host: gwAppHost("appa") });
      expect(res.statusCode).toBe(429);
      expect(edge.usage.records[0]?.outcome).toBe("quota_blocked");
    });

    it("never relays upstream error detail (which could carry the vendor key) to the app", async () => {
      const edge = buildGatewayEdge();
      // Simulate a provider failure whose message embeds a secret-shaped string.
      edge.provider.error = new Error("401 unauthorized: x-api-key sk-ant-SECRET-LEAK");
      const token = await seed(edge.sessions, APP_A);
      const res = await call(edge, token, { host: gwAppHost("appa") });
      // The failure lands before the first byte, so the app gets a generic 502 body
      // (ADR-0034) — either way it must never carry the upstream detail.
      expect(res.statusCode).toBe(502);
      expect(res.body).not.toContain("sk-ant-SECRET-LEAK");
      expect(res.body).not.toContain("x-api-key");
      expect(edge.usage.records[0]?.outcome).toBe("error");
    });

    it("never relays upstream error detail in the SSE error frame either", async () => {
      const edge = buildGatewayEdge();
      // Throw after the first delta so the SSE head is committed and the failure has
      // to travel in-band — the other of the two channels a leak could escape through.
      edge.provider.onDelta = (i) => {
        if (i === 1) throw new Error("401 unauthorized: x-api-key sk-ant-SECRET-LEAK");
      };
      const token = await seed(edge.sessions, APP_A);
      const res = await call(edge, token, { host: gwAppHost("appa") });

      expect(res.statusCode).toBe(200);
      expect(res.body).toContain("event: error");
      expect(res.body).not.toContain("sk-ant-SECRET-LEAK");
      expect(res.body).not.toContain("x-api-key");
      expect(edge.usage.records[0]?.outcome).toBe("error");
    });

    if (layout.name === "split") {
      it("refuses cross-site and sibling Origins and bad Fetch Metadata", async () => {
        const edge = buildGatewayEdge();
        const token = await seed(edge.sessions, APP_A);
        const cfg = layout.config({ auth: testAuthConfig(), allowUnauthenticated: false });
        const goodOrigin = publicOrigin(cfg, "appa");
        const badOrigins = [
          controlOrigin(cfg, "auth"),
          publicOrigin(cfg, "appb"),
          `https://appa.${layout.control}:8080`,
          null,
        ];
        for (const origin of badOrigins) {
          const res = await call(edge, token, {
            host: gwAppHost("appa"),
            origin,
          });
          expect(res.statusCode).toBe(403);
          expect(edge.provider.calls).toHaveLength(0);
          edge.provider.calls.length = 0;
        }
        const opaque = await call(edge, token, {
          host: gwAppHost("appa"),
          originLiteralNull: true,
        });
        expect(opaque.statusCode).toBe(403);
        expect(edge.provider.calls).toHaveLength(0);
        for (const site of ["cross-site", "same-site", "none"]) {
          const res = await call(edge, token, {
            host: gwAppHost("appa"),
            origin: goodOrigin,
            secFetchSite: site,
          });
          expect(res.statusCode).toBe(403);
          expect(edge.provider.calls).toHaveLength(0);
          edge.provider.calls.length = 0;
        }
        const ok = await call(edge, token, {
          host: gwAppHost("appa"),
          origin: goodOrigin,
          secFetchSite: "same-origin",
        });
        expect(ok.statusCode).toBe(200);
      });
    }
  });
});

describe("split layout: auth-host impersonation on the apps domain", () => {
  it("never runs auth handlers or sets cookies on reserved apps hosts", async () => {
    const edge = buildAuthEdge(LAYOUTS[1]);
    const badHosts = [{ host: `auth.${edge.layout.apps}` }, { host: `portal.${edge.layout.apps}` }];
    for (const headers of badHosts) {
      for (const url of [
        "/start?app=appa",
        "/callback?code=x&state=y",
        "/connections/callback",
        "/connections/consent/start",
      ]) {
        const res = await edge.app.inject({ url, headers });
        expect(res.statusCode).toBe(404);
        expect(res.headers["set-cookie"]).toBeUndefined();
      }
    }
    expect(edge.oidc.authorizeRequests).toHaveLength(0);
  });

  it("rejects lookalike /start hosts with 404 and no cookie", async () => {
    const edge = buildAuthEdge(LAYOUTS[1]);
    const control = edge.layout.control;
    const apps = edge.layout.apps;
    const hosts = [
      `xauth.${control}`,
      `a.auth.${control}`,
      `auth.${control}.evil.example`,
      `auth.${control}.`,
      `evil.example:@auth.${control}`,
      `evil.example@app.${apps}`,
      `auth.${control}/path-in-host`,
    ];
    for (const host of hosts) {
      const res = await edge.app.inject({
        url: "/start?app=appa",
        headers: { host },
      });
      expect(res.statusCode).toBe(404);
      expect(res.headers["set-cookie"]).toBeUndefined();
    }
  });

  it("wrong-host redeem does not burn the handoff token", async () => {
    const edge = buildAuthEdge(LAYOUTS[1]);
    const { completeUrl } = await login(edge);
    expect(completeUrl.host).toBe(edge.appHost("appa"));
    expect(completeUrl.host).not.toContain(edge.layout.control);

    const wrong = await redeem(edge, completeUrl, {
      host: `appa.${edge.layout.control}:8080`,
    });
    expect(wrong.statusCode).toBe(404);
    expect(wrong.headers["set-cookie"]).toBeUndefined();

    const ok = await redeem(edge, completeUrl);
    expect(ok.statusCode).toBe(302);
    const replay = await redeem(edge, completeUrl);
    expect(replay.statusCode).toBe(403);
  });
});

describe("split layout: cookie scope across domains", () => {
  it("session and flow cookies stay on the right hosts", async () => {
    const layout = LAYOUTS[1];
    const registry = new FakeRegistry([
      registryEntry({ appId: APP_A, slug: "appa", blobPrefix: "apps/a/1/" }),
      registryEntry({ appId: APP_B, slug: "appb", blobPrefix: "apps/b/1/" }),
    ]);
    const sessions = new FakeSessionStore();
    const oidc = new FakeOidcClient();
    const cfg = layout.config({ auth: testAuthConfig(), allowUnauthenticated: false });
    const app = buildApp({ config: cfg, registry, blob: new FakeBlobReader(), sessions, oidc });
    const edge: AuthEdge = {
      app,
      sessions,
      oidc,
      registry,
      layout,
      authHost: authHostHeader(layout),
      controlHost: new URL(controlOrigin(cfg, "auth")).host,
      appHost: (slug: string) => appHostHeader(layout, slug).host,
    };
    const { completeUrl, flowCookie, callbackRes: loginCallbackRes } = await login(edge);

    function expectNoIdentity(body: string): void {
      expect(body).not.toMatch(/\boid\b/i);
      expect(body).not.toMatch(/@[\w.-]+\.\w+/);
      expect(body).not.toContain('"user"');
    }

    const flowOnApp = await edge.app.inject({
      url: `/callback?code=good&state=x`,
      headers: {
        host: edge.appHost("appa"),
        cookie: `${FLOW_COOKIE}=${flowCookie}`,
      },
    });
    expect(flowOnApp.statusCode).toBe(401);
    expect(flowOnApp.headers["set-cookie"]).toBeUndefined();

    const redeemRes = await redeem(edge, completeUrl);
    expect(redeemRes.statusCode).toBe(302);
    const session = cookieValue(redeemRes, SESSION_COOKIE) as string;
    expect(session).toBeTruthy();

    const crossApp = await edge.app.inject({
      url: "/",
      headers: {
        host: edge.appHost("appb"),
        cookie: `${SESSION_COOKIE}=${session}`,
        "sec-fetch-mode": "navigate",
        accept: "text/html",
      },
    });
    expect(crossApp.statusCode).toBe(302);

    const onAuthApi = await edge.app.inject({
      url: "/_api/me",
      headers: { host: edge.controlHost, cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(onAuthApi.statusCode).toBe(404);
    expectNoIdentity(onAuthApi.body);

    const onAuthConn = await edge.app.inject({
      url: "/connections/foo",
      headers: { host: edge.controlHost, cookie: `${SESSION_COOKIE}=${session}` },
    });
    expect(onAuthConn.statusCode).toBe(503);
    expectNoIdentity(onAuthConn.body);

    const start = await edge.app.inject({
      url: "/start?app=appa&rd=/page",
      headers: edge.authHost,
    });
    const cookies = [start, loginCallbackRes, redeemRes].flatMap((r) => {
      const h = r.headers["set-cookie"];
      return Array.isArray(h) ? h : h ? [h] : [];
    });
    for (const line of cookies) {
      expect(line.startsWith("__Host-")).toBe(true);
      expect(line).toContain("Secure");
      expect(line).toContain("Path=/");
      expect(line).not.toContain("Domain=");
    }
    await app.close();
  });
});

describe("attack: open redirect via /start (extended corpus)", () => {
  it.each(LAYOUTS)("extra corpus for $name", async (layout) => {
    const edge = buildAuthEdge(layout);
    const cfg = layout.config({ auth: testAuthConfig() });
    for (const rd of [
      `//auth.${layout.control}/x`,
      `/\\${layout.apps}`,
      "/%0d%0aSet-Cookie:x=1",
      "/\t/evil.example",
    ]) {
      const res = await edge.app.inject({
        url: `/start?app=appa&rd=${encodeURIComponent(rd)}`,
        headers: edge.authHost,
      });
      expect(res.statusCode).toBe(400);
      expect(edge.oidc.authorizeRequests).toHaveLength(0);
    }
    if (layout.name === "split") {
      const { completeUrl } = await login(edge, { rd: "/page?x=1" });
      const final = await redeem(edge, completeUrl);
      expect(final.statusCode).toBe(302);
      expect(final.headers.location).toBe("/page?x=1");
      expect(completeUrl.origin).toBe(publicOrigin(cfg, "appa"));
    }
  });
});
