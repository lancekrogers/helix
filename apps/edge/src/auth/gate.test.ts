import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { buildApp } from "../app.js";
import { SESSION_COOKIE } from "./cookies.js";
import { hashSessionToken, newSessionToken } from "./sessions.js";
import { controlOrigin, publicOrigin } from "../config.js";
import { splitEdgeConfig, testAuthConfig, testEdgeConfig } from "../test/config.js";
import {
  FakeBlobReader,
  FakeOidcClient,
  FakeRegistry,
  FakeSessionStore,
  registryEntry,
} from "../test/fakes.js";

/**
 * The session gate on app hosts: navigation vs fetch challenges, refresh
 * triggering, per-request visibility re-checks, cookie tossing, /_api/me and
 * logout. (The handoff path itself is adversarial.test.ts.)
 */

const APP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PREFIX = "apps/a/1/";
const HOST = { host: "demo.local.helix.azxlabs.io" };
const NAVIGATE = { "sec-fetch-mode": "navigate" };
const FETCH = { "sec-fetch-mode": "cors" };

interface GatedEdge {
  app: FastifyInstance;
  sessions: FakeSessionStore;
  blob: FakeBlobReader;
}

function buildGatedEdge(registry?: FakeRegistry): GatedEdge {
  const sessions = new FakeSessionStore();
  const blob = new FakeBlobReader();
  blob.set(`${PREFIX}index.html`, { body: "<body>app</body>", contentType: "text/html" });
  blob.set(`${PREFIX}app.js`, { body: "js", contentType: "text/javascript" });
  const app = buildApp({
    config: testEdgeConfig({ auth: testAuthConfig(), allowUnauthenticated: false }),
    registry:
      registry ??
      new FakeRegistry([registryEntry({ appId: APP_ID, slug: "demo", blobPrefix: PREFIX })]),
    blob,
    sessions,
    oidc: new FakeOidcClient(),
  });
  return { app, sessions, blob };
}

async function seedSession(
  sessions: FakeSessionStore,
  opts: {
    appId?: string;
    groups?: string[];
    email?: string;
    refreshDueInMs?: number;
    expiresInMs?: number;
  } = {},
): Promise<string> {
  const id = randomUUID();
  await sessions.createPending({
    id,
    appId: opts.appId ?? APP_ID,
    user: {
      oid: "oid-alice",
      displayName: "Alice Anders",
      name: null,
      email: opts.email ?? null,
      kind: "user",
      groups: opts.groups ?? [],
    },
    refreshDueAt: new Date(Date.now() + (opts.refreshDueInMs ?? 60_000)),
    expiresAt: new Date(Date.now() + (opts.expiresInMs ?? 3_600_000)),
  });
  const token = newSessionToken();
  await sessions.redeem(id, opts.appId ?? APP_ID, hashSessionToken(token));
  return token;
}

function sessionHeader(token: string): Record<string, string> {
  return { cookie: `${SESSION_COOKIE}=${token}` };
}

describe("unauthenticated requests", () => {
  it("redirects navigations into the login flow with the full rd", async () => {
    const edge = buildGatedEdge();
    const res = await edge.app.inject({ url: "/deep/link?q=1", headers: { ...HOST, ...NAVIGATE } });
    expect(res.statusCode).toBe(302);
    const location = new URL(res.headers.location as string);
    expect(location.origin).toBe("https://auth.local.helix.azxlabs.io:8080");
    expect(location.pathname).toBe("/start");
    expect(location.searchParams.get("app")).toBe("demo");
    expect(location.searchParams.get("rd")).toBe("/deep/link?q=1");
    expect(location.searchParams.get("silent")).toBeNull();
    expect(res.headers["cache-control"]).toBe("no-store");
  });

  it("falls back to the Accept sniff when Sec-Fetch-Mode is absent", async () => {
    const edge = buildGatedEdge();
    const nav = await edge.app.inject({ url: "/", headers: { ...HOST, accept: "text/html,*/*" } });
    expect(nav.statusCode).toBe(302);
    const sub = await edge.app.inject({ url: "/app.js", headers: { ...HOST, accept: "*/*" } });
    expect(sub.statusCode).toBe(401);
  });

  it("401s subresources/fetches with no-store and no redirect", async () => {
    const edge = buildGatedEdge();
    const res = await edge.app.inject({ url: "/app.js", headers: { ...HOST, ...FETCH } });
    expect(res.statusCode).toBe(401);
    expect(res.headers.location).toBeUndefined();
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.json()).toMatchObject({ error: { code: "unauthorized" } });
    expect(edge.blob.requests).toHaveLength(0); // never touched the blob
  });

  it("the 404/410 ladder still answers before the gate", async () => {
    const edge = buildGatedEdge(
      new FakeRegistry([registryEntry({ appId: APP_ID, slug: "old", archived: true })]),
    );
    const unknown = await edge.app.inject({
      url: "/",
      headers: { host: "nope.local.helix.azxlabs.io", ...NAVIGATE },
    });
    expect(unknown.statusCode).toBe(404);
    const archived = await edge.app.inject({
      url: "/",
      headers: { host: "old.local.helix.azxlabs.io", ...NAVIGATE },
    });
    expect(archived.statusCode).toBe(410);
  });
});

describe("authenticated requests", () => {
  it("serves assets with a valid session", async () => {
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions);
    const res = await edge.app.inject({
      url: "/",
      headers: { ...HOST, ...NAVIGATE, ...sessionHeader(token) },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("app");
  });

  it("treats an expired session as absent (interactive login)", async () => {
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions, { expiresInMs: -1000 });
    const res = await edge.app.inject({
      url: "/",
      headers: { ...HOST, ...NAVIGATE, ...sessionHeader(token) },
    });
    expect(res.statusCode).toBe(302);
    expect(new URL(res.headers.location as string).searchParams.get("silent")).toBeNull();
  });

  it("a session for app A is worthless on app B", async () => {
    const edge = buildGatedEdge(
      new FakeRegistry([
        registryEntry({ appId: APP_ID, slug: "demo", blobPrefix: PREFIX }),
        registryEntry({
          appId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
          slug: "other",
          blobPrefix: PREFIX,
        }),
      ]),
    );
    const token = await seedSession(edge.sessions); // bound to APP_ID (demo)
    const res = await edge.app.inject({
      url: "/",
      headers: { host: "other.local.helix.azxlabs.io", ...NAVIGATE, ...sessionHeader(token) },
    });
    expect(res.statusCode).toBe(302); // not authenticated there
  });
});

describe("silent refresh triggering", () => {
  it("redirects a refresh-due navigation with silent=1", async () => {
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions, { refreshDueInMs: -1000 });
    const res = await edge.app.inject({
      url: "/page",
      headers: { ...HOST, ...NAVIGATE, ...sessionHeader(token) },
    });
    expect(res.statusCode).toBe(302);
    const location = new URL(res.headers.location as string);
    expect(location.searchParams.get("silent")).toBe("1");
    expect(location.searchParams.get("rd")).toBe("/page");
  });

  it("keeps serving refresh-due subresources until hard expiry", async () => {
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions, { refreshDueInMs: -1000 });
    const res = await edge.app.inject({
      url: "/app.js",
      headers: { ...HOST, ...FETCH, ...sessionHeader(token) },
    });
    expect(res.statusCode).toBe(200);
  });

  it("401s refresh-due /_api/* fetches with refresh_required", async () => {
    // Unlike passive assets, the API namespace treats the refresh due-time
    // as an authorization boundary: the group snapshot is stale, so fetches
    // stop being served on it (matters for the M4 gateway, which is fetches).
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions, { refreshDueInMs: -1000 });
    const res = await edge.app.inject({
      url: "/_api/me",
      headers: { ...HOST, ...FETCH, ...sessionHeader(token) },
    });
    expect(res.statusCode).toBe(401);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.json()).toMatchObject({ error: { code: "refresh_required" } });
  });

  it("still serves /_api/me before the refresh is due", async () => {
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions);
    const res = await edge.app.inject({
      url: "/_api/me",
      headers: { ...HOST, ...FETCH, ...sessionHeader(token) },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ user: { displayName: "Alice Anders" } });
  });
});

describe("per-request visibility re-check", () => {
  function groupEdge(groups: string[]): { edge: GatedEdge; tokenPromise: Promise<string> } {
    const registry = new FakeRegistry([
      registryEntry({
        appId: APP_ID,
        slug: "demo",
        blobPrefix: PREFIX,
        visibilityMode: "group",
        visibilityGroupIds: ["eng-team"],
      }),
    ]);
    const edge = buildGatedEdge(registry);
    return { edge, tokenPromise: seedSession(edge.sessions, { groups }) };
  }

  it("admits a snapshot containing the group", async () => {
    const { edge, tokenPromise } = groupEdge(["eng-team"]);
    const res = await edge.app.inject({
      url: "/",
      headers: { ...HOST, ...NAVIGATE, ...sessionHeader(await tokenPromise) },
    });
    expect(res.statusCode).toBe(200);
  });

  it("sends a non-member's navigation through silent re-auth (fresh snapshot)", async () => {
    const { edge, tokenPromise } = groupEdge(["other-team"]);
    const res = await edge.app.inject({
      url: "/",
      headers: { ...HOST, ...NAVIGATE, ...sessionHeader(await tokenPromise) },
    });
    expect(res.statusCode).toBe(302);
    expect(new URL(res.headers.location as string).searchParams.get("silent")).toBe("1");

    const fetchRes = await edge.app.inject({
      url: "/app.js",
      headers: { ...HOST, ...FETCH, ...sessionHeader(await tokenPromise) },
    });
    expect(fetchRes.statusCode).toBe(401);
  });
});

describe("password apps also admit SSO sessions", () => {
  function passwordEdge(): GatedEdge {
    return buildGatedEdge(
      new FakeRegistry([
        registryEntry({
          appId: APP_ID,
          slug: "demo",
          blobPrefix: PREFIX,
          visibilityMode: "password",
        }),
      ]),
    );
  }

  it("cold navigation goes to the same-origin password form (which links to SSO)", async () => {
    const res = await passwordEdge().app.inject({ url: "/", headers: { ...HOST, ...NAVIGATE } });
    expect(res.statusCode).toBe(302);
    const loc = new URL(res.headers.location as string);
    expect(loc.host).toBe("demo.local.helix.azxlabs.io:8080");
    expect(loc.pathname).toBe("/_auth/login");
  });

  it("serves a real (SSO) session — identity is irrelevant once authenticated", async () => {
    const edge = passwordEdge();
    const token = await seedSession(edge.sessions, { groups: ["eng-team"] });
    const res = await edge.app.inject({
      url: "/",
      headers: { ...HOST, ...NAVIGATE, ...sessionHeader(token) },
    });
    expect(res.statusCode).toBe(200);
  });

  it("refresh-due routes to SSO silent re-auth, not the password form", async () => {
    const edge = passwordEdge();
    const token = await seedSession(edge.sessions, { refreshDueInMs: -1000 });
    const res = await edge.app.inject({
      url: "/",
      headers: { ...HOST, ...NAVIGATE, ...sessionHeader(token) },
    });
    expect(res.statusCode).toBe(302);
    const loc = new URL(res.headers.location as string);
    expect(loc.host).toBe("auth.local.helix.azxlabs.io:8080");
    expect(loc.pathname).toBe("/start");
    expect(loc.searchParams.get("silent")).toBe("1");
  });
});

describe("attack: cookie tossing at the gate", () => {
  it("ignores near-name shadow cookies entirely", async () => {
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions);
    const res = await edge.app.inject({
      url: "/",
      headers: {
        ...HOST,
        ...NAVIGATE,
        cookie: `session=evil; __host-session=evil; ${SESSION_COOKIE}=${token}`,
      },
    });
    expect(res.statusCode).toBe(200); // the real cookie still works
  });

  it("treats conflicting duplicates of the session cookie as absent", async () => {
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions);
    const res = await edge.app.inject({
      url: "/",
      headers: {
        ...HOST,
        ...NAVIGATE,
        cookie: `${SESSION_COOKIE}=evil; ${SESSION_COOKIE}=${token}`,
      },
    });
    expect(res.statusCode).toBe(302); // ambiguity = unauthenticated, never "evil wins"
  });
});

describe("/_api/me", () => {
  it("returns the minimal user object for a valid session", async () => {
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions);
    const res = await edge.app.inject({
      url: "/_api/me",
      headers: { ...HOST, ...FETCH, ...sessionHeader(token) },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    // `seedSession` captures no address, and the key is still sent as an
    // explicit null — apps branch on the value, never on the key's presence.
    expect(res.json()).toEqual({
      user: { id: "oid-alice", displayName: "Alice Anders", email: null },
    });
  });

  it("returns the captured address when the session has one", async () => {
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions, { email: "alice@azx.dev" });
    const res = await edge.app.inject({
      url: "/_api/me",
      headers: { ...HOST, ...FETCH, ...sessionHeader(token) },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      user: { id: "oid-alice", displayName: "Alice Anders", email: "alice@azx.dev" },
    });
  });

  it("never projects the group snapshot, whatever the session carries", async () => {
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions, { groups: ["group-eng", "group-admin"] });
    const res = await edge.app.inject({
      url: "/_api/me",
      headers: { ...HOST, ...FETCH, ...sessionHeader(token) },
    });
    const body = res.json() as { user: Record<string, unknown> };
    expect(Object.keys(body.user).sort()).toEqual(["displayName", "email", "id"]);
    expect(res.body).not.toContain("group-eng");
  });

  it("401s without a session and 404s off app hosts", async () => {
    const edge = buildGatedEdge();
    expect(
      (await edge.app.inject({ url: "/_api/me", headers: { ...HOST, ...FETCH } })).statusCode,
    ).toBe(401);
    expect(
      (await edge.app.inject({ url: "/_api/me", headers: { host: "auth.local.helix.azxlabs.io" } }))
        .statusCode,
    ).toBe(404);
    expect(
      (await edge.app.inject({ url: "/_api/me", headers: { host: "local.helix.azxlabs.io" } }))
        .statusCode,
    ).toBe(404);
  });
});

describe("POST /_auth/logout", () => {
  function logoutInject(
    edge: GatedEdge,
    token: string | null,
    origin?: string,
  ): Promise<LightMyRequestResponse> {
    return edge.app.inject({
      method: "POST",
      url: "/_auth/logout",
      headers: {
        ...HOST,
        ...(origin ? { origin } : {}),
        ...(token ? sessionHeader(token) : {}),
      },
    });
  }

  it("deletes the session and clears the cookie for a same-origin POST", async () => {
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions);
    const res = await logoutInject(edge, token, "https://demo.local.helix.azxlabs.io:8080");
    expect(res.statusCode).toBe(204);
    expect(String(res.headers["set-cookie"])).toContain(`${SESSION_COOKIE}=;`);
    expect(await edge.sessions.lookup(hashSessionToken(token), APP_ID)).toBeNull();
  });

  it("refuses cross-origin and origin-less logouts (CSRF)", async () => {
    const edge = buildGatedEdge();
    const token = await seedSession(edge.sessions);
    expect(
      (await logoutInject(edge, token, "https://other.local.helix.azxlabs.io:8080")).statusCode,
    ).toBe(403);
    expect((await logoutInject(edge, token, "https://evil.example")).statusCode).toBe(403);
    expect((await logoutInject(edge, token)).statusCode).toBe(403);
    // The session survives all of those.
    expect(await edge.sessions.lookup(hashSessionToken(token), APP_ID)).not.toBeNull();
  });
});

describe("the dev bypass and the unconfigured edge", () => {
  it("EDGE_DEV_ALLOW_UNAUTHENTICATED skips only the gate", async () => {
    const sessions = new FakeSessionStore();
    const blob = new FakeBlobReader();
    blob.set(`${PREFIX}index.html`, { body: "<body>open</body>", contentType: "text/html" });
    const app = buildApp({
      config: testEdgeConfig({ auth: testAuthConfig(), allowUnauthenticated: true }),
      registry: new FakeRegistry([
        registryEntry({ appId: APP_ID, slug: "demo", blobPrefix: PREFIX }),
      ]),
      blob,
      sessions,
      oidc: new FakeOidcClient(),
    });
    const res = await app.inject({ url: "/", headers: { ...HOST, ...NAVIGATE } });
    expect(res.statusCode).toBe(200);
    // Unknown slugs still 404 — the bypass is not "serve anything".
    expect(
      (await app.inject({ url: "/", headers: { host: "nope.local.helix.azxlabs.io" } })).statusCode,
    ).toBe(404);
    await app.close();
  });

  it("an edge without the auth stack fails closed on app serving", async () => {
    const app = buildApp({
      config: testEdgeConfig({ allowUnauthenticated: false }), // auth: null
      registry: new FakeRegistry([
        registryEntry({ appId: APP_ID, slug: "demo", blobPrefix: PREFIX }),
      ]),
      blob: new FakeBlobReader(),
    });
    const res = await app.inject({ url: "/", headers: HOST });
    expect(res.statusCode).toBe(503);
    await app.close();
  });
});

describe("split layout gate redirects", () => {
  function splitEdge(registry?: FakeRegistry): GatedEdge {
    const sessions = new FakeSessionStore();
    const blob = new FakeBlobReader();
    blob.set(`${PREFIX}index.html`, { body: "<body>app</body>", contentType: "text/html" });
    const app = buildApp({
      config: splitEdgeConfig({ auth: testAuthConfig(), allowUnauthenticated: false }),
      registry:
        registry ??
        new FakeRegistry([
          registryEntry({
            appId: APP_ID,
            slug: "demo",
            blobPrefix: PREFIX,
            visibilityMode: "internal",
          }),
        ]),
      blob,
      sessions,
      oidc: new FakeOidcClient(),
    });
    return { app, sessions, blob };
  }

  it("sends SSO navigations to auth on the control domain", async () => {
    const cfg = splitEdgeConfig({ auth: testAuthConfig(), allowUnauthenticated: false });
    const edge = splitEdge();
    const res = await edge.app.inject({
      url: "/deep/link?q=1",
      headers: {
        host: new URL(publicOrigin(cfg, "demo")).host,
        ...NAVIGATE,
      },
    });
    expect(res.statusCode).toBe(302);
    const location = new URL(res.headers.location as string);
    expect(location.origin).toBe(controlOrigin(cfg, "auth"));
    expect(location.pathname).toBe("/start");
  });

  it("sends password-app cold navigations to the apps-domain login form", async () => {
    const cfg = splitEdgeConfig({ auth: testAuthConfig(), allowUnauthenticated: false });
    const edge = splitEdge(
      new FakeRegistry([
        registryEntry({
          appId: APP_ID,
          slug: "demo",
          blobPrefix: PREFIX,
          visibilityMode: "password",
        }),
      ]),
    );
    const res = await edge.app.inject({
      url: "/",
      headers: { host: new URL(publicOrigin(cfg, "demo")).host, ...NAVIGATE },
    });
    expect(res.statusCode).toBe(302);
    const loc = new URL(res.headers.location as string);
    expect(loc.origin).toBe(publicOrigin(cfg, "demo"));
    expect(loc.pathname).toBe("/_auth/login");
  });
});
