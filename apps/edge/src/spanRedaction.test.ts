import { randomUUID } from "node:crypto";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import { DataCapabilitySchema, INTERNAL_AUTH_HEADER } from "@azx-pbc/shared";
import { hashDevToken } from "@azx-pbc/shared/devToken";
import { spanUrlAttributes } from "@azx-pbc/shared/logging";
import {
  ATTR_REASON,
  ATTR_USAGE_BASIS,
  CUT_CHARGE_BASES,
  FORBIDDEN_URL_ATTRS,
  SPAN_CONSENT_STATUS_DEV,
  SPAN_CONSENT_STATUS_EDGE,
  SPAN_LLM,
} from "@azx-pbc/shared/telemetry";
import { withRootSpan } from "./telemetry.js";
import { buildApp } from "./app.js";
import { buildDevGateway } from "./devGateway/app.js";
import type { DevTokenStore } from "./devGateway/devTokenStore.js";
import { SESSION_COOKIE } from "./auth/cookies.js";
import { hashSessionToken, newSessionToken } from "./auth/sessions.js";
import { testAuthConfig, testDevGatewayConfig, testEdgeConfig } from "./test/config.js";
import {
  FakeAppDataStore,
  FakeBlobReader,
  FakeLlmProvider,
  FakeOidcClient,
  FakePortalProvider,
  FakeRegistry,
  FakeSessionStore,
  FakeUsageStore,
  registryEntry,
} from "./test/fakes.js";
import { LlmProviderError } from "./gateway/provider.js";

/**
 * ADR-0037 decision 10's redaction case — the direct sibling of
 * `apps/edge/src/logging.test.ts`, and written the same way on purpose: it
 * scans **every attribute of every span** for the planted secret rather than
 * checking one field. A per-field assertion passes forever while a span added
 * later leaks; a global scan fails.
 *
 * Decision 6 is the rule this enforces, and the ADR's own consequences call it
 * "the most likely way the decision decays" — a rule someone must keep applying
 * at each new span. This is the part that does not depend on remembering.
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

/** Distinctive enough that a substring match cannot be a false negative. */
const HANDOFF_TOKEN = "eyJhbGciOiJIUzI1NiJ9.PLANTED-HANDOFF-TOKEN.signature";
const OIDC_CODE = "PLANTED-OIDC-AUTHORIZATION-CODE";
const UPSTREAM_KEY = "sk-PLANTED-UPSTREAM-API-KEY";
const SAS_SIG = "PLANTED-AZURE-SAS-SIGNATURE";

/** Every credential-bearing URL the platform actually produces. */
const CREDENTIAL_URLS = [
  `/_auth/complete?token=${HANDOFF_TOKEN}&rd=/`,
  `/callback?code=${OIDC_CODE}&state=abc`,
  `/callback?error=access_denied&error_description=${OIDC_CODE}`,
  `/_api/fetch/https://api.vendor.test/v1/users?api_key=${UPSTREAM_KEY}`,
  `/_api/fetch/https://acct.blob.core.windows.net/c/b.txt?sig=${SAS_SIG}&se=2026-01-01`,
  // Percent-encoded target: the whole thing hides in the path, where a
  // parameter scan never runs.
  `/_api/fetch/https%3A%2F%2Fapi.vendor.test%2Fv1%3Fapi_key%3D${UPSTREAM_KEY}`,
  // Userinfo in the target — `origin` strips it, but assert rather than assume.
  `/_api/fetch/https://user:${UPSTREAM_KEY}@api.vendor.test/v1`,
];

const SECRETS = [HANDOFF_TOKEN, OIDC_CODE, UPSTREAM_KEY, SAS_SIG];

describe("span attributes never carry a credential", () => {
  it("leaks nothing from any credential-bearing URL, across every attribute", async () => {
    for (const url of CREDENTIAL_URLS) {
      await withRootSpan("test.route", spanUrlAttributes(url), async () => {});
    }

    // The global scan: serialize everything and look for the plants.
    const dump = JSON.stringify(recording.spans().map((s) => s.attributes));
    for (const secret of SECRETS) {
      expect(dump, `a span attribute leaked ${secret}`).not.toContain(secret);
    }
  });

  it("records no attribute key that carries a whole URL", async () => {
    for (const url of CREDENTIAL_URLS) {
      await withRootSpan("test.route", spanUrlAttributes(url), async () => {});
    }

    for (const span of recording.spans()) {
      for (const key of Object.keys(span.attributes)) {
        expect(FORBIDDEN_URL_ATTRS, `${key} is a whole-URL attribute`).not.toContain(key);
      }
    }
  });

  it("drops the query wholesale, not by parameter name", async () => {
    // Stronger than the log serializer, deliberately: a credential under a name
    // `SENSITIVE_PARAMS` has never heard of still cannot reach a span.
    const url = "/_auth/complete?unknown_param_name=PLANTED-UNLISTED-SECRET";
    await withRootSpan("test.route", spanUrlAttributes(url), async () => {});

    const dump = JSON.stringify(recording.spans().map((s) => s.attributes));
    expect(dump).not.toContain("PLANTED-UNLISTED-SECRET");
    expect(dump).not.toContain("?");
  });

  it("still records enough path to be worth having", async () => {
    // Redaction that deleted everything would pass every test above and be
    // useless. `url.path` must still say which route ran, and for the
    // fetch-proxy which upstream was called.
    await withRootSpan(
      "test.route",
      spanUrlAttributes(`/_api/fetch/https://api.vendor.test/v1/users?api_key=${UPSTREAM_KEY}`),
      async () => {},
    );

    const path = recording.spans()[0]?.attributes["url.path"];
    expect(path).toContain("api.vendor.test");
    expect(path).toContain("/v1/users");
    expect(path).not.toContain(UPSTREAM_KEY);
  });

  it("keeps the constant auth routes recognisable", async () => {
    await withRootSpan(
      "test.route",
      spanUrlAttributes(`/_auth/complete?token=${HANDOFF_TOKEN}`),
      async () => {},
    );
    expect(recording.spans()[0]?.attributes["url.path"]).toBe("/_auth/complete");
  });

  /**
   * ADR-0042 review finding 1's regression guard. The data routes are the
   * first parameterized routes `spanUrlAttributes` was ever pointed at, and
   * four of them carry an app-chosen KEY as the path's last segment — under
   * prefix grants those keys are unbounded and attacker-choosable, so an
   * `url.path` there is app data written into a retained backend (it fires even
   * on a 404, so an unauthenticated prober chooses the strings). The wrapper
   * (`withDataSpans`) therefore records no path at all — `http.route` plus
   * `helix.data.verb` identify the route. This drives the REAL handlers with a
   * planted key in the URL and scans every attribute of every span, so
   * re-adding a path attribute fails here rather than leaking quietly.
   */
  describe("the app-data gateway's parameterized routes (ADR-0042 finding 1)", () => {
    const APP_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const HOST = "notes.local.helix.azxlabs.io";
    // The edge's Origin check is exact same-origin, port included (as in
    // `data.test.ts` — the host header omits it, the Origin must carry it).
    const ORIGIN = `https://${HOST}:8080`;
    /** A key an app might plausibly derive from a person — the leak case. */
    const PLANTED_KEY = "PLANTED-PATIENT-ssn-123";

    function buildDataEdge() {
      const app = buildApp({
        config: testEdgeConfig({ auth: testAuthConfig(), allowUnauthenticated: false }),
        registry: new FakeRegistry([
          registryEntry({
            appId: APP_ID,
            slug: "notes",
            blobPrefix: "apps/c/1/",
            visibilityMode: "public",
            data: DataCapabilitySchema.parse({
              user: false,
              sharedReadPrefixes: ["record:"],
            }),
          }),
        ]),
        blob: new FakeBlobReader(),
        sessions: new FakeSessionStore(),
        oidc: new FakeOidcClient(),
        usage: new FakeUsageStore(),
        appData: new FakeAppDataStore(),
      });
      return app;
    }

    it("never puts the app-chosen key on a span — not even on a 404 probe", async () => {
      const app = buildDataEdge();
      const res = await app.inject({
        method: "GET",
        // 404 (nothing seeded): the span still fires — that is the point.
        url: `/_api/data/shared/record:${PLANTED_KEY}`,
        headers: { host: HOST },
      });
      expect(res.statusCode).toBe(404);
      await app.close();

      expect(recording.spans().length).toBeGreaterThan(0);
      const dump = JSON.stringify(recording.spans().map((s) => s.attributes));
      expect(dump, "an app-data span leaked the requested key").not.toContain(PLANTED_KEY);
      // And the route is identified without any path at all.
      for (const span of recording.spans()) {
        expect(span.attributes["url.path"]).toBeUndefined();
      }
    });

    it("never puts the key on a successful write's span either", async () => {
      // A user-scope PUT that SUCCEEDS (the authenticated happy path) — the
      // strongest case, because the key is real stored data, not a probe.
      const sessions = new FakeSessionStore();
      const token = newSessionToken();
      const id = randomUUID();
      await sessions.createPending({
        id,
        appId: APP_ID,
        user: {
          oid: "alice",
          displayName: "Alice",
          name: null,
          email: null,
          kind: "user",
          groups: [],
        },
        refreshDueAt: new Date(Date.now() + 60_000),
        expiresAt: new Date(Date.now() + 3_600_000),
      });
      await sessions.redeem(id, APP_ID, hashSessionToken(token));
      const app = buildApp({
        config: testEdgeConfig({ auth: testAuthConfig(), allowUnauthenticated: false }),
        registry: new FakeRegistry([
          registryEntry({
            appId: APP_ID,
            slug: "notes",
            blobPrefix: "apps/c/1/",
            visibilityMode: "internal",
            data: DataCapabilitySchema.parse({ user: true }),
          }),
        ]),
        blob: new FakeBlobReader(),
        sessions,
        oidc: new FakeOidcClient(),
        usage: new FakeUsageStore(),
        appData: new FakeAppDataStore(),
      });
      const put = await app.inject({
        method: "PUT",
        url: `/_api/data/user/draft:${PLANTED_KEY}`,
        headers: {
          host: HOST,
          origin: ORIGIN,
          "content-type": "application/json",
          cookie: `${SESSION_COOKIE}=${token}`,
        },
        payload: { note: "x" },
      });
      expect(put.statusCode).toBe(200);
      await app.close();

      const dump = JSON.stringify(recording.spans().map((s) => s.attributes));
      expect(dump, "an app-data span leaked the written key").not.toContain(PLANTED_KEY);
    });
  });

  /**
   * The auth host's `/connections/*` reverse proxy. The vendor's
   * redirect lands here with `code` and `state` in the URL (this route's
   * spans are fixed to `url.path` only),
   * and the request carries material an attacker can plant themselves — the
   * forged internal header the proxy must strip. Drives the REAL route
   * through `buildApp` with everything planted, then scans every attribute of
   * every span, so a later attribute addition fails here instead of leaking.
   */
  describe("the /connections/* proxy route", () => {
    const CONSENT_CODE = "PLANTED-CONSENT-CODE";
    const CONSENT_STATE = "PLANTED-CONSENT-STATE";
    const FORGED_INTERNAL = "PLANTED-FORGED-INTERNAL-TOKEN";
    const AUTH_HOST = { host: "auth.local.helix.azxlabs.io" };

    function buildProxyEdge() {
      return buildApp({
        config: testEdgeConfig({ auth: testAuthConfig(), internalSecret: Buffer.alloc(32, 7) }),
        registry: new FakeRegistry([
          registryEntry({
            appId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            slug: "notes",
            blobPrefix: "apps/e/1/",
          }),
        ]),
        blob: new FakeBlobReader(),
        sessions: new FakeSessionStore(),
        oidc: new FakeOidcClient(),
        portal: new FakePortalProvider(),
      });
    }

    it("leaks no code, state, or internal-header value — across every attribute", async () => {
      const app = buildProxyEdge();
      const res = await app.inject({
        method: "GET",
        url: `/connections/callback?code=${CONSENT_CODE}&state=${CONSENT_STATE}`,
        headers: { ...AUTH_HOST, [INTERNAL_AUTH_HEADER]: FORGED_INTERNAL },
      });
      expect(res.statusCode).toBe(200);
      await app.close();

      expect(recording.spans().length).toBeGreaterThan(0);
      const dump = JSON.stringify(recording.spans().map((s) => s.attributes));
      for (const secret of [CONSENT_CODE, CONSENT_STATE, FORGED_INTERNAL]) {
        expect(dump, `a span attribute leaked ${secret}`).not.toContain(secret);
      }
      // The query is dropped wholesale — not even a `?` survives.
      expect(dump).not.toContain("?");
      for (const span of recording.spans()) {
        for (const key of Object.keys(span.attributes)) {
          expect(FORBIDDEN_URL_ATTRS, `${key} is a whole-URL attribute`).not.toContain(key);
        }
      }
      // And the route is still identifiable — `url.path` only, no query.
      const routeSpan = recording.spans().find((s) => s.name === "helix.auth.connections.proxy");
      expect(routeSpan?.attributes["url.path"]).toBe("/connections/callback");
    });
  });

  /**
   * The consent start route. The URL carries an app-chosen `attempt`
   * correlation tag (unbounded, attacker-choosable on a public-URL route — the
   * ADR-0042 finding-1 class of value), and the consult's answer is a vendor
   * authorize URL carrying `state` + the PKCE challenge, which the route 302s
   * to. Neither may reach a span: the query is dropped wholesale, and the
   * redirect target is never an attribute. Drives the REAL route on both the
   * guarded-refusal and the started paths, then scans every attribute of
   * every span.
   */
  describe("the consent start route", () => {
    const APP_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff";
    const HOST = { host: "notes.local.helix.azxlabs.io" };
    const ORIGIN = `https://notes.local.helix.azxlabs.io:8080`;
    const POPUP_HEADERS = {
      "sec-fetch-site": "same-origin",
      referer: `${ORIGIN}/page`,
    };
    const ATTEMPT_TAG = "PLANTED-ATTEMPT-CORRELATION-TAG";
    const VENDOR_STATE = "PLANTED-VENDOR-OAUTH-STATE";
    const VENDOR_CHALLENGE = "PLANTED-PKCE-CHALLENGE";
    const START = `/_api/connections/asana/start?attempt=${ATTEMPT_TAG}`;

    it("leaks no attempt tag or vendor protocol value — on the refusal path", async () => {
      // A cross-site navigation (every hostile header combination refuses) —
      // the cheapest route to the span, and the one a prober drives.
      const app = buildApp({
        config: testEdgeConfig({ auth: testAuthConfig(), internalSecret: Buffer.alloc(32, 7) }),
        registry: new FakeRegistry([
          registryEntry({ appId: APP_ID, slug: "notes", blobPrefix: "apps/f/1/" }),
        ]),
        blob: new FakeBlobReader(),
        sessions: new FakeSessionStore(),
        oidc: new FakeOidcClient(),
        portal: new FakePortalProvider(),
      });
      const res = await app.inject({ method: "GET", url: START, headers: HOST });
      expect(res.statusCode).toBe(403);
      await app.close();

      expect(recording.spans().length).toBeGreaterThan(0);
      const dump = JSON.stringify(recording.spans().map((s) => s.attributes));
      expect(dump, "a span attribute leaked the attempt tag").not.toContain(ATTEMPT_TAG);
      expect(dump).not.toContain("?");
      for (const span of recording.spans()) {
        for (const key of Object.keys(span.attributes)) {
          expect(FORBIDDEN_URL_ATTRS, `${key} is a whole-URL attribute`).not.toContain(key);
        }
      }
    });

    it("leaks nothing from the started path — the authorize URL never touches a span", async () => {
      const sessions = new FakeSessionStore();
      // The consult answers `started` with a vendor authorize URL carrying the
      // state + PKCE challenge; the route 302s it. Neither value may reach a
      // span attribute.
      const portal = new FakePortalProvider();
      portal.status = 200;
      portal.headers = { "content-type": "application/json" };
      portal.body = JSON.stringify({
        outcome: "started",
        authorizeUrl: `https://vendor.example/oauth/authorize?state=${VENDOR_STATE}&code_challenge=${VENDOR_CHALLENGE}&code_challenge_method=S256`,
      });

      const token = newSessionToken();
      const id = randomUUID();
      await sessions.createPending({
        id,
        appId: APP_ID,
        user: {
          oid: "alice",
          displayName: "Alice",
          name: null,
          email: null,
          kind: "user",
          groups: [],
        },
        refreshDueAt: new Date(Date.now() + 60_000),
        expiresAt: new Date(Date.now() + 3_600_000),
      });
      await sessions.redeem(id, APP_ID, hashSessionToken(token));
      const app = buildApp({
        config: testEdgeConfig({ auth: testAuthConfig(), internalSecret: Buffer.alloc(32, 7) }),
        registry: new FakeRegistry([
          registryEntry({ appId: APP_ID, slug: "notes", blobPrefix: "apps/f/1/" }),
        ]),
        blob: new FakeBlobReader(),
        sessions,
        oidc: new FakeOidcClient(),
        portal,
      });
      const res = await app.inject({
        method: "GET",
        url: START,
        headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
      });
      expect(res.statusCode).toBe(302);
      await app.close();

      const dump = JSON.stringify(recording.spans().map((s) => s.attributes));
      for (const secret of [ATTEMPT_TAG, VENDOR_STATE, VENDOR_CHALLENGE]) {
        expect(dump, `a span attribute leaked ${secret}`).not.toContain(secret);
      }
      expect(dump).not.toContain("?");
      expect(dump).not.toContain("vendor.example");
      const routeSpan = recording.spans().find((s) => s.name === "helix.consent.start");
      expect(routeSpan?.attributes["url.path"]).toBe("/_api/connections/asana/start");
    });
  });

  /**
   * The dev-gateway's consent start route. The whole point of the
   * journey is that the dev bearer token never leaves the authenticated POST —
   * and the popup URL the route returns carries only
   * the single-use nonce, while the consult's vendor state + PKCE challenge
   * stay protocol-internal. Drives the REAL dev-gateway route on the started
   * path with everything planted, then scans every attribute of every span.
   */
  describe("the dev-gateway consent start route", () => {
    const DEV_BEARER = "PLANTED-DEV-BEARER-TOKEN-VALUE";
    const VENDOR_STATE = "PLANTED-VENDOR-OAUTH-STATE";
    const VENDOR_CHALLENGE = "PLANTED-PKCE-CHALLENGE";
    const DEV_APP_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

    function buildDevConsentGateway(portal: FakePortalProvider): FastifyInstance {
      const tokens: DevTokenStore = {
        async resolve(tokenHash) {
          return tokenHash === hashDevToken(DEV_BEARER)
            ? {
                appId: DEV_APP_ID,
                developerOid: "oid-developer",
                origins: ["https://myapp.lovable.app"],
                expiresAt: new Date(Date.now() + 60_000),
                revokedAt: null,
              }
            : null;
        },
        async originAllowed() {
          return false;
        },
        async close() {},
      };
      return buildDevGateway({
        config: testDevGatewayConfig({ internalSecret: Buffer.alloc(32, 7) }),
        registry: new FakeRegistry([
          registryEntry({ appId: DEV_APP_ID, slug: "myapp", blobPrefix: "apps/d/1/" }),
        ]),
        devTokens: tokens,
        appData: null,
        usage: null,
        llmProvider: null,
        egress: null,
        instructionKey: null,
        portal,
      });
    }

    it("leaks no dev bearer token or vendor protocol value — across every attribute", async () => {
      const portal = new FakePortalProvider();
      portal.status = 200;
      portal.headers = { "content-type": "application/json" };
      portal.body = JSON.stringify({
        outcome: "started",
        authorizeUrl: `https://vendor.example/oauth/authorize?state=${VENDOR_STATE}&code_challenge=${VENDOR_CHALLENGE}&code_challenge_method=S256`,
      });
      const app = buildDevConsentGateway(portal);

      const res = await app.inject({
        method: "POST",
        url: "/myapp/_api/connections/asana/start",
        headers: {
          host: "dev-api.local.helix.azxlabs.io",
          authorization: `Bearer ${DEV_BEARER}`,
          origin: "https://myapp.lovable.app",
        },
      });
      expect(res.statusCode).toBe(200);
      const popupUrl = res.json<{ popupUrl: string }>().popupUrl;
      // The response's URL itself is the first scan surface: the bearer token
      // must never leave the authenticated POST.
      expect(popupUrl).not.toContain(DEV_BEARER);
      expect(popupUrl).not.toContain(VENDOR_STATE);
      expect(popupUrl).not.toContain(VENDOR_CHALLENGE);
      await app.close();

      // Then every span on the path — the route span and any it carries.
      const nonce = new URL(popupUrl).searchParams.get("nonce") ?? "absent";
      const dump = JSON.stringify(recording.spans().map((s) => s.attributes));
      for (const secret of [DEV_BEARER, VENDOR_STATE, VENDOR_CHALLENGE, nonce]) {
        expect(dump, `a span attribute leaked ${secret}`).not.toContain(secret);
      }
      expect(dump).not.toContain("?");
      expect(dump).not.toContain("vendor.example");
      for (const span of recording.spans()) {
        for (const key of Object.keys(span.attributes)) {
          expect(FORBIDDEN_URL_ATTRS, `${key} is a whole-URL attribute`).not.toContain(key);
        }
      }
    });
  });

  /**
   * ADR-0031 as amended: the app-facing connection-status read. The route's
   * own response is the status word only, and the internal read carries the
   * session's verified identity — none of which may reach a span attribute.
   */
  describe("the connection-status route (prod + dev)", () => {
    const APP_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff";
    const HOST = { host: "notes.local.helix.azxlabs.io" };

    it("the prod read leaks no identity across every attribute", async () => {
      const sessions = new FakeSessionStore();
      const portal = new FakePortalProvider();
      portal.status = 200;
      portal.headers = { "content-type": "application/json" };
      portal.body = JSON.stringify({ status: "connected" });

      const token = newSessionToken();
      const id = randomUUID();
      await sessions.createPending({
        id,
        appId: APP_ID,
        user: {
          oid: "PLANTED-USER-OID",
          displayName: "Alice",
          name: null,
          email: null,
          kind: "user",
          groups: [],
        },
        refreshDueAt: new Date(Date.now() + 60_000),
        expiresAt: new Date(Date.now() + 3_600_000),
      });
      await sessions.redeem(id, APP_ID, hashSessionToken(token));
      const app = buildApp({
        config: testEdgeConfig({ auth: testAuthConfig(), internalSecret: Buffer.alloc(32, 7) }),
        registry: new FakeRegistry([
          registryEntry({ appId: APP_ID, slug: "notes", blobPrefix: "apps/f/1/" }),
        ]),
        blob: new FakeBlobReader(),
        sessions,
        oidc: new FakeOidcClient(),
        portal,
      });
      const res = await app.inject({
        method: "GET",
        url: "/_api/connections/asana/status",
        headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}` },
      });
      expect(res.statusCode).toBe(200);
      await app.close();

      const dump = JSON.stringify(recording.spans().map((s) => s.attributes));
      expect(dump, "a span attribute leaked the caller's identity").not.toContain(
        "PLANTED-USER-OID",
      );
      expect(dump).not.toContain("?");
      const routeSpan = recording.spans().find((s) => s.name === SPAN_CONSENT_STATUS_EDGE);
      expect(routeSpan?.attributes["url.path"]).toBe("/_api/connections/asana/status");
      for (const span of recording.spans()) {
        for (const key of Object.keys(span.attributes)) {
          expect(FORBIDDEN_URL_ATTRS, `${key} is a whole-URL attribute`).not.toContain(key);
        }
      }
    });

    it("the dev read leaks no dev bearer token across every attribute", async () => {
      const DEV_BEARER = "PLANTED-DEV-BEARER-TOKEN-VALUE";
      const DEV_APP_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
      const tokens: DevTokenStore = {
        async resolve(tokenHash) {
          return tokenHash === hashDevToken(DEV_BEARER)
            ? {
                appId: DEV_APP_ID,
                developerOid: "oid-developer",
                origins: ["https://myapp.lovable.app"],
                expiresAt: new Date(Date.now() + 60_000),
                revokedAt: null,
              }
            : null;
        },
        async originAllowed() {
          return false;
        },
        async close() {},
      };
      const portal = new FakePortalProvider();
      portal.status = 200;
      portal.headers = { "content-type": "application/json" };
      portal.body = JSON.stringify({ status: "connected" });
      const app = buildDevGateway({
        config: testDevGatewayConfig({ internalSecret: Buffer.alloc(32, 7) }),
        registry: new FakeRegistry([
          registryEntry({ appId: DEV_APP_ID, slug: "myapp", blobPrefix: "apps/d/1/" }),
        ]),
        devTokens: tokens,
        appData: null,
        usage: null,
        llmProvider: null,
        egress: null,
        instructionKey: null,
        portal,
      });

      const res = await app.inject({
        method: "GET",
        url: "/myapp/_api/connections/asana/status",
        headers: {
          host: "dev-api.local.helix.azxlabs.io",
          authorization: `Bearer ${DEV_BEARER}`,
          origin: "https://myapp.lovable.app",
        },
      });
      expect(res.statusCode).toBe(200);
      await app.close();

      const dump = JSON.stringify(recording.spans().map((s) => s.attributes));
      expect(dump, "a span attribute leaked the dev bearer token").not.toContain(DEV_BEARER);
      expect(dump).not.toContain("?");
      const routeSpan = recording.spans().find((s) => s.name === SPAN_CONSENT_STATUS_DEV);
      expect(routeSpan?.attributes["url.path"]).toBe("/myapp/_api/connections/asana/status");
      for (const span of recording.spans()) {
        for (const key of Object.keys(span.attributes)) {
          expect(FORBIDDEN_URL_ATTRS, `${key} is a whole-URL attribute`).not.toContain(key);
        }
      }
    });
  });
});

describe("LLM admission denials", () => {
  const APP_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
  const HOST = "deny.local.helix.azxlabs.io";
  const ORIGIN = `https://${HOST}:8080`;
  const MODEL = "claude-opus-4-8";
  const PLANTED_PROMPT = "PLANTED-PROMPT-FRAGMENT-admission-deny";
  const PLANTED_OID = "oid-planted-admission-deny";

  it("never leaks prompt, oid, or URL on spans or admission-denied metrics", async () => {
    const sessions = new FakeSessionStore();
    const usage = new FakeUsageStore();
    usage.spendTodayMicro = 1_000_000;
    const id = randomUUID();
    await sessions.createPending({
      id,
      appId: APP_ID,
      user: {
        oid: PLANTED_OID,
        displayName: "Deny",
        name: null,
        email: null,
        kind: "user",
        groups: [],
      },
      refreshDueAt: new Date(Date.now() + 60_000),
      expiresAt: new Date(Date.now() + 3_600_000),
    });
    const token = newSessionToken();
    await sessions.redeem(id, APP_ID, hashSessionToken(token));

    const app = buildApp({
      config: testEdgeConfig({ auth: testAuthConfig(), allowUnauthenticated: false }),
      registry: new FakeRegistry([
        registryEntry({
          appId: APP_ID,
          slug: "deny",
          blobPrefix: "apps/e/3/",
          llm: { models: [MODEL], dollarsPerDay: 1 },
        }),
      ]),
      blob: new FakeBlobReader(),
      sessions,
      oidc: new FakeOidcClient(),
      llmProvider: new FakeLlmProvider(),
      usage,
    });

    const res = await app.inject({
      method: "POST",
      url: "/_api/llm/chat",
      headers: {
        host: HOST,
        "sec-fetch-mode": "cors",
        "content-type": "application/json",
        origin: ORIGIN,
        cookie: `${SESSION_COOKIE}=${token}`,
      },
      payload: {
        model: MODEL,
        messages: [{ role: "user", content: PLANTED_PROMPT }],
      },
    });
    expect(res.statusCode).toBe(429);
    await app.close();

    const spanDump = JSON.stringify(recording.spans().map((s) => s.attributes));
    const metricDump = JSON.stringify((await recording.metrics()).map((p) => p.attributes));
    for (const dump of [spanDump, metricDump]) {
      expect(dump, "leaked the planted prompt").not.toContain(PLANTED_PROMPT);
      expect(dump, "leaked the planted oid").not.toContain(PLANTED_OID);
      expect(dump, "leaked a URL query").not.toContain("?");
    }
    for (const span of recording.spans()) {
      for (const key of Object.keys(span.attributes)) {
        expect(FORBIDDEN_URL_ATTRS, `${key} is a whole-URL attribute`).not.toContain(key);
      }
    }
    const llmSpan = recording.spans().find((s) => s.name === SPAN_LLM);
    expect(llmSpan?.attributes[ATTR_REASON]).toBe("app_budget_day");
  });

  it("never leaks prompt, oid, or URL on a platform ceiling refusal", async () => {
    const sessions = new FakeSessionStore();
    const usage = new FakeUsageStore();
    usage.platformSpendTodayMicro = 2_000_000;
    const id = randomUUID();
    await sessions.createPending({
      id,
      appId: APP_ID,
      user: {
        oid: PLANTED_OID,
        displayName: "Deny",
        name: null,
        email: null,
        kind: "user",
        groups: [],
      },
      refreshDueAt: new Date(Date.now() + 60_000),
      expiresAt: new Date(Date.now() + 3_600_000),
    });
    const token = newSessionToken();
    await sessions.redeem(id, APP_ID, hashSessionToken(token));

    const app = buildApp({
      config: testEdgeConfig({
        auth: testAuthConfig(),
        allowUnauthenticated: false,
        llm: {
          endpoint: "https://api.anthropic.com",
          path: "/v1/messages",
          anthropicVersion: "2023-06-01",
          connection: "anthropic",
          openai: {
            endpoint: "https://api.openai.com",
            path: "/v1/chat/completions",
            connection: "openai",
          },
          defaultDollarsPerDay: 50,
          platformDollarsPerDay: 1,
        },
      }),
      registry: new FakeRegistry([
        registryEntry({
          appId: APP_ID,
          slug: "deny",
          blobPrefix: "apps/e/3/",
          llm: { models: [MODEL], dollarsPerDay: 10 },
        }),
      ]),
      blob: new FakeBlobReader(),
      sessions,
      oidc: new FakeOidcClient(),
      llmProvider: new FakeLlmProvider(),
      usage,
    });

    const res = await app.inject({
      method: "POST",
      url: "/_api/llm/chat",
      headers: {
        host: HOST,
        "sec-fetch-mode": "cors",
        "content-type": "application/json",
        origin: ORIGIN,
        cookie: `${SESSION_COOKIE}=${token}`,
      },
      payload: {
        model: MODEL,
        messages: [{ role: "user", content: PLANTED_PROMPT }],
      },
    });
    expect(res.statusCode).toBe(503);
    await app.close();

    const spanDump = JSON.stringify(recording.spans().map((s) => s.attributes));
    const metricDump = JSON.stringify((await recording.metrics()).map((p) => p.attributes));
    for (const dump of [spanDump, metricDump]) {
      expect(dump).not.toContain(PLANTED_PROMPT);
      expect(dump).not.toContain(PLANTED_OID);
      expect(dump).not.toContain("?");
    }
    const llmSpan = recording.spans().find((s) => s.name === SPAN_LLM);
    expect(llmSpan?.attributes[ATTR_REASON]).toBe("platform_ceiling");
  });
});

describe("cut and failed LLM gateway calls", () => {
  const APP_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const HOST = "cut.local.helix.azxlabs.io";
  const ORIGIN = `https://${HOST}:8080`;
  const MODEL = "claude-opus-4-8";
  const PLANTED_PROMPT = "PLANTED-PROMPT-FRAGMENT-cut-charge";
  const PLANTED_OID = "oid-planted-cut-charge";

  it("never leaks prompt, oid, URL, or scope on spans or cut-charge metrics", async () => {
    const sessions = new FakeSessionStore();
    const provider = new FakeLlmProvider();
    provider.errorAfterDeltas = new LlmProviderError("openai stream ended without a usage block");
    provider.deltas = ["x"];
    const usage = new FakeUsageStore();
    const id = randomUUID();
    await sessions.createPending({
      id,
      appId: APP_ID,
      user: {
        oid: PLANTED_OID,
        displayName: "Cut Charge",
        name: null,
        email: null,
        kind: "user",
        groups: [],
      },
      refreshDueAt: new Date(Date.now() + 60_000),
      expiresAt: new Date(Date.now() + 3_600_000),
    });
    const token = newSessionToken();
    await sessions.redeem(id, APP_ID, hashSessionToken(token));

    const app = buildApp({
      config: testEdgeConfig({ auth: testAuthConfig(), allowUnauthenticated: false }),
      registry: new FakeRegistry([
        registryEntry({
          appId: APP_ID,
          slug: "cut",
          blobPrefix: "apps/d/2/",
          llm: { models: [MODEL], dollarsPerDay: 1 },
        }),
      ]),
      blob: new FakeBlobReader(),
      sessions,
      oidc: new FakeOidcClient(),
      llmProvider: provider,
      usage,
    });

    const res = await app.inject({
      method: "POST",
      url: "/_api/llm/chat",
      headers: {
        host: HOST,
        "sec-fetch-mode": "cors",
        "content-type": "application/json",
        origin: ORIGIN,
        cookie: `${SESSION_COOKIE}=${token}`,
      },
      payload: {
        model: MODEL,
        messages: [{ role: "user", content: PLANTED_PROMPT }],
        stream: true,
      },
    });
    expect(res.statusCode).toBe(200);
    await app.close();

    const spanDump = JSON.stringify(recording.spans().map((s) => s.attributes));
    const metricDump = JSON.stringify((await recording.metrics()).map((p) => p.attributes));
    for (const dump of [spanDump, metricDump]) {
      expect(dump, "leaked the planted prompt").not.toContain(PLANTED_PROMPT);
      expect(dump, "leaked the planted oid").not.toContain(PLANTED_OID);
      expect(dump, "leaked a URL query").not.toContain("?");
      expect(dump, "leaked a lease scope").not.toMatch(/llm:(app|user):/);
    }
    for (const span of recording.spans()) {
      for (const key of Object.keys(span.attributes)) {
        expect(FORBIDDEN_URL_ATTRS, `${key} is a whole-URL attribute`).not.toContain(key);
      }
    }
    const llmSpan = recording.spans().find((s) => s.name === SPAN_LLM);
    expect(CUT_CHARGE_BASES).toContain(llmSpan?.attributes[ATTR_USAGE_BASIS]);
  });
});
