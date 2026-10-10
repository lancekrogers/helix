import { randomBytes } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import {
  INTERNAL_AUDIENCE,
  INTERNAL_AUTH_HEADER,
  INTERNAL_JWT_TYP,
  INTERNAL_TTL_SECONDS,
} from "@azx-pbc/shared";
import { buildApp } from "../app.js";
import { deriveInternalKey } from "../internalJwt.js";
import { FLOW_COOKIE } from "../auth/cookies.js";
import { controlOrigin } from "../config.js";
import { splitEdgeConfig, testAuthConfig, testEdgeConfig } from "../test/config.js";
import {
  FakeBlobReader,
  FakeOidcClient,
  FakePortalProvider,
  FakeRegistry,
  FakeSessionStore,
  registryEntry,
} from "../test/fakes.js";
import { withServer } from "../test/socket.js";
import { HttpPortalProvider, type PortalProvider } from "./portalProvider.js";
import type { EdgeConfig } from "../config.js";

/**
 * The auth-host `/connections/*` reverse proxy.
 * The portal-ward half runs against a REAL local listener (`withServer`), so
 * the assertions see the wire the way the portal will — one internal header,
 * the minted one, with nothing inbound surviving the hop. The in-process
 * `FakePortalProvider` covers the handler-level contract without a socket.
 */

const SECRET = randomBytes(32);
const INTERNAL_KEY = deriveInternalKey(SECRET);
const APP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const AUTH_HOST = { host: "auth.local.helix.azxlabs.io" };
const APP_HOST = { host: "demo.local.helix.azxlabs.io" };

/** Count occurrences of a header name in a rawHeaders pair list. */
function headerCount(rawHeaders: string[], name: string): number {
  let n = 0;
  for (let i = 0; i < rawHeaders.length; i += 2) {
    if (rawHeaders[i]?.toLowerCase() === name) n++;
  }
  return n;
}

/**
 * The verify rule of the portal side (apps/portal/src/internalJwt.ts),
 * replayed here with plain jose — aud + typ + max age, fail closed.
 */
async function verifiesUnderPortalRule(token: string, key: Buffer): Promise<boolean> {
  try {
    await jwtVerify(token, key, {
      algorithms: ["HS256"],
      typ: INTERNAL_JWT_TYP,
      audience: INTERNAL_AUDIENCE,
      clockTolerance: 5,
      maxTokenAge: INTERNAL_TTL_SECONDS,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * A fake portal built without listen (then bound by `withServer`): a
 * `/connections/*` route that captures what actually arrived on the wire —
 * headers as pairs, so a duplicated header is countable — and answers a fixed
 * page with a marker header.
 */
class FakePortalApp {
  readonly app: FastifyInstance;
  readonly calls: {
    method: string;
    url: string;
    headers: Record<string, unknown>;
    rawHeaders: string[];
    body: string;
  }[] = [];

  constructor() {
    this.app = Fastify({ logger: false });
    // A portal that reads its bodies raw: the passthrough parser keeps
    // `req.raw` consumable and stops Fastify 415ing non-JSON content types.
    this.app.removeAllContentTypeParsers();
    this.app.addContentTypeParser("*", (_req, payload, done) => done(null, payload));
    for (const method of ["GET", "POST"] as const) {
      this.app.route({
        method,
        url: "/connections/*",
        handler: async (req, reply) => {
          const chunks: Buffer[] = [];
          for await (const chunk of req.raw) chunks.push(chunk as Buffer);
          this.calls.push({
            method: req.method,
            url: req.url,
            headers: req.headers,
            rawHeaders: req.raw.rawHeaders,
            body: Buffer.concat(chunks).toString("utf8"),
          });
          reply
            .header("content-type", "text/html; charset=utf-8")
            .header("x-portal-proof", "served-by-portal")
            .send("<html>served by portal</html>");
        },
      });
    }
  }

  call(): (typeof this.calls)[number] | undefined {
    return this.calls.at(-1);
  }
}

function buildProxyEdge(
  opts: { portal?: PortalProvider | null; internalSecret?: Buffer | null } = {},
): FastifyInstance {
  const portal = opts.portal === undefined ? new FakePortalProvider() : opts.portal;
  const internalSecret = opts.internalSecret === undefined ? SECRET : opts.internalSecret;
  return buildApp({
    config: testEdgeConfig({ auth: testAuthConfig(), internalSecret }),
    registry: new FakeRegistry([
      registryEntry({ appId: APP_ID, slug: "demo", blobPrefix: "apps/a/1/" }),
    ]),
    blob: new FakeBlobReader(),
    sessions: new FakeSessionStore(),
    oidc: new FakeOidcClient(),
    portal,
  });
}

describe("the /connections/* reverse proxy on the auth host", () => {
  it("reaches the portal with the internal header present and verified", async () => {
    const fake = new FakePortalApp();
    await withServer(fake.app, async (base) => {
      const portal = new HttpPortalProvider(base);
      const app = buildProxyEdge({ portal });
      const res = await app.inject({
        method: "GET",
        url: "/connections/anything",
        headers: AUTH_HOST,
      });
      expect(res.statusCode).toBe(200);
      expect(res.body).toBe("<html>served by portal</html>");
      // The portal's own response headers pass through.
      expect(res.headers["x-portal-proof"]).toBe("served-by-portal");
      await portal.close();
      await app.close();
    });
    expect(fake.calls).toHaveLength(1);
    const seen = fake.call()!;
    expect(seen.method).toBe("GET");
    expect(seen.url).toBe("/connections/anything");
    expect(
      await verifiesUnderPortalRule(seen.headers[INTERNAL_AUTH_HEADER] as string, INTERNAL_KEY),
    ).toBe(true);
  });

  it("forwards the query string and streams a POST body through", async () => {
    const fake = new FakePortalApp();
    await withServer(fake.app, async (base) => {
      const portal = new HttpPortalProvider(base);
      const app = buildProxyEdge({ portal });
      const post = await app.inject({
        method: "POST",
        url: "/connections/nonce-entry",
        headers: { ...AUTH_HOST, "content-type": "application/x-www-form-urlencoded" },
        payload: "nonce=PLANTED-NONCE",
      });
      expect(post.statusCode).toBe(200);
      await portal.close();
      await app.close();
    });
    const seen = fake.call()!;
    // Path and query reach the portal verbatim — the vendor's `code`/`state`
    // round-trip depends on it.
    expect(seen.url).toBe("/connections/nonce-entry");
    expect(seen.body).toBe("nonce=PLANTED-NONCE");
  });

  it("strips a forged inbound internal header — the portal sees exactly one, the minted one", async () => {
    const fake = new FakePortalApp();
    await withServer(fake.app, async (base) => {
      const portal = new HttpPortalProvider(base);
      const app = buildProxyEdge({ portal });
      const res = await app.inject({
        method: "GET",
        url: "/connections/callback?code=PLANTED-CODE&state=PLANTED-STATE",
        headers: {
          ...AUTH_HOST,
          cookie: `${FLOW_COOKIE}=forged-flow-cookie`,
          [INTERNAL_AUTH_HEADER]: "PLANTED-FORGED-TOKEN",
          "x-helix-request-id": "forged-request-id",
        },
      });
      expect(res.statusCode).toBe(200);
      await portal.close();
      await app.close();
    });
    expect(fake.calls).toHaveLength(1);
    const seen = fake.call()!;
    // Exactly ONE internal header on the wire, and it verifies under the
    // portal's rule with the edge's key — the planted forgery is gone
    // (the strip rule).
    expect(headerCount(seen.rawHeaders, INTERNAL_AUTH_HEADER)).toBe(1);
    const token = seen.headers[INTERNAL_AUTH_HEADER];
    expect(token).toBeTruthy();
    expect(token).not.toBe("PLANTED-FORGED-TOKEN");
    expect(await verifiesUnderPortalRule(token as string, INTERNAL_KEY)).toBe(true);
    // The auth host's flow cookie never crosses the seam — the consent
    // surface keys identity off `state` server-side.
    expect(seen.headers.cookie).toBeUndefined();
    // A forged correlation id cannot shadow the edge's own.
    expect(seen.headers["x-helix-request-id"]).not.toBe("forged-request-id");
    // Only the safelist rides along — no client-chosen header survives.
    expect(seen.headers["x-arbitrary"]).toBeUndefined();
  });

  it("sets the auth-callback cache/referrer posture on the proxied response", async () => {
    const portal = new FakePortalProvider();
    // The portal sends neither header — the edge's posture must hold anyway.
    portal.headers = { "content-type": "text/html; charset=utf-8" };
    const app = buildProxyEdge({ portal });
    const res = await app.inject({
      method: "GET",
      url: "/connections/callback?code=x&state=y",
      headers: AUTH_HOST,
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
    await app.close();
  });

  it("never forwards the safelisted set's neighbours — an inbound traceparent is dropped", async () => {
    const portal = new FakePortalProvider();
    const app = buildProxyEdge({ portal });
    await app.inject({
      method: "GET",
      url: "/connections/callback?code=x&state=y",
      headers: {
        ...AUTH_HOST,
        traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      },
    });
    // The seam request's header map is the safelisted set only; the minted
    // internal token rides beside it (`internalToken`), never inside it.
    const seen = portal.requests[0]!;
    expect(seen.headers["traceparent"]).toBeUndefined();
    expect(seen.headers[INTERNAL_AUTH_HEADER]).toBeUndefined();
    await app.close();
  });

  it("refuses dot segments inside the prefix and never proxies them", async () => {
    const portal = new FakePortalProvider();
    const app = buildProxyEdge({ portal });
    const res = await app.inject({
      method: "GET",
      url: "/connections/../start",
      headers: AUTH_HOST,
    });
    expect(res.statusCode).toBe(404);
    expect(portal.requests).toHaveLength(0);
    await app.close();
  });

  it("refuses an oversized POST before proxying it", async () => {
    const portal = new FakePortalProvider();
    const app = buildProxyEdge({ portal });
    const res = await app.inject({
      method: "POST",
      url: "/connections/callback",
      headers: { ...AUTH_HOST, "content-type": "application/octet-stream" },
      payload: Buffer.alloc(1024 * 1024 + 1),
    });
    expect(res.statusCode).toBe(413);
    expect(portal.requests).toHaveLength(0);
    await app.close();
  });

  it("split layout: callbacks on auth.<apps> 404 without calling the portal", async () => {
    const portal = new FakePortalProvider();
    const cfg = splitEdgeConfig({ auth: testAuthConfig(), internalSecret: SECRET });
    const app = buildApp({
      config: cfg,
      registry: new FakeRegistry([
        registryEntry({ appId: APP_ID, slug: "demo", blobPrefix: "apps/a/1/" }),
      ]),
      blob: new FakeBlobReader(),
      sessions: new FakeSessionStore(),
      oidc: new FakeOidcClient(),
      portal,
    });
    const appsAuth = { host: `auth.${cfg.baseDomain}:8080` };
    const res = await app.inject({
      method: "GET",
      url: "/connections/callback?code=x&state=y",
      headers: appsAuth,
    });
    expect(res.statusCode).toBe(404);
    expect(portal.requests).toHaveLength(0);

    const controlAuth = { host: new URL(controlOrigin(cfg, "auth")).host };
    const ok = await app.inject({
      method: "GET",
      url: "/connections/callback?code=x&state=y",
      headers: controlAuth,
    });
    expect(ok.statusCode).toBe(200);
    expect(portal.requests).toHaveLength(1);
    await app.close();
  });
});

describe("fail-closed when unconfigured", () => {
  it("503s distinguishably with no portal provider, and nothing proxies", async () => {
    const portal = new FakePortalProvider();
    const app = buildProxyEdge({ portal: null });
    const res = await app.inject({
      method: "GET",
      url: "/connections/anything",
      headers: AUTH_HOST,
    });
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain("not configured");
    expect(res.headers["retry-after"]).toBe("5");
    expect(portal.requests).toHaveLength(0);
    // No crash: the edge keeps serving.
    const health = await app.inject({ url: "/health", headers: { host: "localhost:8080" } });
    expect(health.statusCode).toBe(200);
    await app.close();
  });

  it("503s when the internal mint key is unset even with a portal wired", async () => {
    const portal = new FakePortalProvider();
    const app = buildProxyEdge({ portal, internalSecret: null });
    const res = await app.inject({
      method: "GET",
      url: "/connections/anything",
      headers: AUTH_HOST,
    });
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain("not configured");
    expect(portal.requests).toHaveLength(0);
    await app.close();
  });
});

describe("nothing else on the auth host changes (regression)", () => {
  it("/start still begins the OIDC flow; /callback still errors without the flow cookie; / still 404s", async () => {
    const app = buildProxyEdge();
    const start = await app.inject({
      url: "/start?app=demo&rd=/page",
      headers: AUTH_HOST,
    });
    expect(start.statusCode).toBe(302);
    expect(start.headers.location).toContain("https://idp.example/authorize");
    expect(start.headers["set-cookie"]).toBeTruthy();

    const callback = await app.inject({ url: "/callback?code=x&state=y", headers: AUTH_HOST });
    expect(callback.statusCode).toBe(400);

    const root = await app.inject({ url: "/", headers: AUTH_HOST });
    expect(root.statusCode).toBe(404);
    await app.close();
  });

  it("/health keeps answering the platform contract", async () => {
    const app = buildProxyEdge();
    const res = await app.inject({ url: "/health", headers: { host: "localhost:8080" } });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ status: "ok", service: "helix-edge" });
    await app.close();
  });
});

describe("the two-router discipline holds around the new route", () => {
  it("an app host still serves /connections/x as an asset — the proxy never engages", async () => {
    const blob = new FakeBlobReader();
    blob.set("apps/a/1/connections/x", { body: "app asset" });
    const app = buildApp({
      config: testEdgeConfig({ auth: testAuthConfig(), internalSecret: SECRET }),
      registry: new FakeRegistry([
        registryEntry({ appId: APP_ID, slug: "demo", blobPrefix: "apps/a/1/" }),
      ]),
      blob,
      sessions: new FakeSessionStore(),
      oidc: new FakeOidcClient(),
      portal: new FakePortalProvider(),
    });
    const res = await app.inject({ url: "/connections/x", headers: APP_HOST });
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe("app asset");
    await app.close();
  });

  it("a platform host 404s the prefix, as it always did", async () => {
    const app = buildProxyEdge();
    const res = await app.inject({ url: "/connections/x", headers: { host: "localhost:8080" } });
    expect(res.statusCode).toBe(404);
    await app.close();
  });
});

/** Pins the config field's parse: EDGE_PORTAL_URL → portalUrl, fail-closed default. */
describe("EDGE_PORTAL_URL config", () => {
  it("defaults to null and parses a set value", async () => {
    const { loadConfig } = await import("../config.js");
    const base = {
      DATABASE_URL: "postgresql://unused",
      AZURE_STORAGE_CONNECTION_STRING:
        "DefaultEndpointsProtocol=https;AccountName=a;AccountKey=KQ==;BlobEndpoint=https://acct.blob.core.windows.net",
      EDGE_TLS_CERT_FILE: "/tmp/c.pem",
      EDGE_TLS_KEY_FILE: "/tmp/k.pem",
      NODE_ENV: "test",
    };
    expect(loadConfig({ ...base }).portalUrl).toBeNull();
    expect(loadConfig({ ...base, EDGE_PORTAL_URL: "http://portal:3001" }).portalUrl).toBe(
      "http://portal:3001",
    );
  });

  it("is null in the shared test config default", () => {
    const cfg: EdgeConfig = testEdgeConfig();
    expect(cfg.portalUrl).toBeNull();
  });
});
