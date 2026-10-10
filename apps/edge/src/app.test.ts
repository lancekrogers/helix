import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { HealthCheck } from "@azx-pbc/shared";
import { buildApp } from "./app.js";
import type { EdgeConfig } from "./config.js";
import { FakeBlobReader, FakeRegistry, registryEntry } from "./test/fakes.js";
import { TRUST_PROXY_CHECK_NAME, TRUST_PROXY_WINDOW } from "./routing/trustProxyHealth.js";

const APP_ID = "11111111-1111-4111-8111-111111111111";
const PREFIX = `apps/${APP_ID}/1/`;

function testConfig(overrides: Partial<EdgeConfig> = {}): EdgeConfig {
  return {
    baseDomain: "local.helix.azxlabs.io",
    databaseUrl: "postgresql://unused",
    blob: {
      provider: "azure",
      endpoint: "http://azurite:10000/devstoreaccount1",
      container: "app-bundles",
      auth: {
        mode: "shared-key",
        accountName: "devstoreaccount1",
        accountKey: Buffer.from("dGVzdA==", "base64"),
      },
    },
    auth: null,
    allowUnauthenticated: true,
    allowPublicApps: true,
    allowPasswordApps: true,
    publicScheme: "https",
    publicPort: 8080,
    tls: null,
    reconcileIntervalMs: 60_000,
    statementTimeoutMs: 10_000,
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
      platformDollarsPerDay: 0,
      maxAppInFlight: 0,
      maxUserInFlight: 0,
      maxInFlight: 0,
      maxCallMs: 600_000,
    },
    anonRateLimit: { max: 0, windowMs: 60_000 },
    imgSrcExtra: [],
    trustProxy: false,
    fetch: {
      egressUrl: null,
      instructionSecret: null,
      timeoutMs: 30_000,
      maxBodyBytes: 10 * 1024 * 1024,
      maxAppInFlight: 0,
    },
    internalSecret: null,
    portalUrl: null,
    ...overrides,
  };
}

function buildTestEdge(opts: {
  config?: Partial<EdgeConfig>;
  registry?: FakeRegistry;
  blob?: FakeBlobReader;
}): { app: FastifyInstance; blob: FakeBlobReader } {
  const blob = opts.blob ?? new FakeBlobReader();
  const registry =
    opts.registry ??
    new FakeRegistry([registryEntry({ appId: APP_ID, slug: "demo", blobPrefix: PREFIX })]);
  const app = buildApp({ config: testConfig(opts.config), registry, blob });
  return { app, blob };
}

const HOST = { host: "demo.local.helix.azxlabs.io" };

let edge: { app: FastifyInstance; blob: FakeBlobReader };

beforeAll(async () => {
  edge = buildTestEdge({});
  edge.blob.set(`${PREFIX}index.html`, {
    body: "<!doctype html><body>demo</body>",
    contentType: "text/html; charset=utf-8",
    etag: '"html-1"',
  });
  edge.blob.set(`${PREFIX}assets/app.js`, {
    body: "console.log(1)",
    contentType: "text/javascript; charset=utf-8",
    etag: '"js-1"',
  });
  edge.blob.set(`${PREFIX}favicon.svg`, {
    body: "<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>",
    contentType: "image/svg+xml",
  });
  edge.blob.set(`${PREFIX}vendor..min.js`, {
    body: "//..",
    contentType: "text/javascript; charset=utf-8",
  });
  // Decoy assets inside the reserved namespaces — these must never serve.
  edge.blob.set(`${PREFIX}_api/me`, { body: "leaked", contentType: "text/plain" });
  edge.blob.set(`${PREFIX}_auth/complete`, { body: "leaked", contentType: "text/plain" });
  await edge.app.ready();
});

afterAll(async () => {
  await edge.app.close();
});

describe("platform hosts", () => {
  it("serves /health with the shared health contract", async () => {
    const res = await edge.app.inject({ url: "/health", headers: { host: "localhost:8080" } });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ status: "ok", service: "helix-edge" });
    // The registry-freshness sub-check is part of the contract an alert keys on.
    expect(res.json().checks?.[0]?.name).toBe("registry-projection");
    expect(res.json().checks?.[0]?.status).toBe("ok");
    // So is the trust-proxy one (ADR-0011) — nothing proxied yet in this suite.
    expect(res.json().checks?.[1]?.name).toBe("trust-proxy");
    expect(res.json().checks?.[1]?.status).toBe("ok");
  });

  it("404s everything else", async () => {
    const res = await edge.app.inject({ url: "/whatever", headers: { host: "localhost:8080" } });
    expect(res.statusCode).toBe(404);
  });
});

/**
 * The trust-proxy self-report, through the real app (ADR-0011). Inject's
 * loopback peer stands in for the ingress — the same convention config.test.ts
 * established — and the test configs default `trustProxy: false`
 * (`src/test/config.ts`), so the degraded arm needs no override at all.
 */
describe("the trust-proxy /health sub-check", () => {
  const N = TRUST_PROXY_WINDOW;
  const healthCheck = async (app: FastifyInstance) => {
    const res = await app.inject({ url: "/health", headers: { host: "localhost:8080" } });
    const body = res.json<{ status: string; checks?: HealthCheck[] }>();
    return {
      rollup: body.status,
      check: body.checks?.find((c) => c.name === TRUST_PROXY_CHECK_NAME),
    };
  };

  it("starts at 'not enough proxied traffic yet' and degrades after N untrusted proxied requests", async () => {
    const { app } = buildTestEdge({});
    await app.ready();
    const { check } = await healthCheck(app);
    expect(check).toMatchObject({
      status: "ok",
      detail: `not enough proxied traffic yet (0/${N})`,
    });

    // The live defect (ADR-0011's 2026-09-03 section), reproduced: an
    // X-Forwarded-For-carrying ingress in front of an edge that trusts nothing.
    for (let i = 0; i < N; i++) {
      await app.inject({
        url: "/health",
        headers: { host: "localhost:8080", "x-forwarded-for": "203.0.113.7" },
      });
    }
    const degraded = await healthCheck(app); // this read carries no header, so it counts nothing
    expect(degraded.check?.status).toBe("degraded");
    expect(degraded.check?.detail).toContain("EDGE_TRUST_PROXY");
    expect(degraded.check?.metrics?.windowResolved).toBe(0);
    expect(degraded.rollup).toBe("degraded"); // the worst state wins the roll-up
    await app.close();
  });

  it("reads ok once the walk resolves, with forwardedResolved to show for it", async () => {
    const { app } = buildTestEdge({ config: { trustProxy: "127.0.0.0/8" } });
    await app.ready();
    for (let i = 0; i < N; i++) {
      await app.inject({
        url: "/health",
        headers: { host: "localhost:8080", "x-forwarded-for": "203.0.113.7" },
      });
    }
    const { check, rollup } = await healthCheck(app);
    expect(check?.status).toBe("ok");
    expect(check?.detail).toBeUndefined();
    expect(check?.metrics?.forwardedResolved).toBeGreaterThan(0);
    expect(check?.metrics?.windowResolved).toBeGreaterThan(0);
    expect(rollup).toBe("ok");
    await app.close();
  });

  it("never counts requests without the header — probes and local dev cannot degrade it", async () => {
    const { app } = buildTestEdge({ config: { trustProxy: "127.0.0.0/8" } });
    await app.ready();
    for (let i = 0; i < N + 10; i++) {
      await app.inject({ url: "/health", headers: { host: "localhost:8080" } });
    }
    const { check } = await healthCheck(app);
    expect(check).toMatchObject({
      status: "ok",
      detail: `not enough proxied traffic yet (0/${N})`,
      metrics: { forwardedSeen: 0 },
    });
    await app.close();
  });
});

function expectAppCspPair(headers: { [key: string]: unknown }) {
  const enforced = headers["content-security-policy"] as string;
  const reportOnly = headers["content-security-policy-report-only"] as string;
  expect(enforced).toBeDefined();
  expect(reportOnly).toBeDefined();
  expect(enforced).toContain("img-src https:");
  expect(enforced).not.toContain("object-src");
  expect(reportOnly).toContain("object-src 'none'");
  expect(reportOnly).toContain("img-src 'self' data: blob:");
}

describe("app hosts: asset serving", () => {
  it("serves an asset with forwarded headers and nosniff", async () => {
    const res = await edge.app.inject({ url: "/assets/app.js", headers: HOST });
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe("console.log(1)");
    expect(res.headers["content-type"]).toBe("text/javascript; charset=utf-8");
    expect(res.headers.etag).toBe('"js-1"');
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    // Non-HTML: cacheable briefly, private (M3 makes app content authed)…
    expect(res.headers["cache-control"]).toBe("private, max-age=300");
    // …and still CSP'd — every app response carries the policy, because any
    // browser-active document type (SVG, XML) can execute script.
    expectAppCspPair(res.headers);
    expect(res.headers["content-security-policy"]).toContain("connect-src 'self'");
  });

  it("sends the full app CSP on browser-active non-HTML documents (SVG)", async () => {
    const res = await edge.app.inject({ url: "/favicon.svg", headers: HOST });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toBe("image/svg+xml");
    const csp = res.headers["content-security-policy"] as string;
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("form-action 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expectAppCspPair(res.headers);
  });

  it("refuses service-worker registration fetches (Service-Worker header)", async () => {
    const res = await edge.app.inject({
      url: "/assets/app.js",
      headers: { ...HOST, "service-worker": "script" },
    });
    expect(res.statusCode).toBe(403);
    // The same asset without the registration header serves normally.
    const plain = await edge.app.inject({ url: "/assets/app.js", headers: HOST });
    expect(plain.statusCode).toBe(200);
  });

  it("serves / as index.html with CSP and no-cache", async () => {
    const res = await edge.app.inject({ url: "/", headers: HOST });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("demo");
    expectAppCspPair(res.headers);
    expect(res.headers["content-security-policy"]).toContain("connect-src 'self'");
    expect(res.headers["cache-control"]).toBe("no-cache");
  });

  it("answers HEAD with headers and no body", async () => {
    const res = await edge.app.inject({ method: "HEAD", url: "/assets/app.js", headers: HOST });
    expect(res.statusCode).toBe(200);
    expect(res.headers.etag).toBe('"js-1"');
    expect(res.body).toBe("");
  });

  it("returns 304 for a matching If-None-Match", async () => {
    const res = await edge.app.inject({
      url: "/assets/app.js",
      headers: { ...HOST, "if-none-match": '"js-1"' },
    });
    expect(res.statusCode).toBe(304);
    expect(res.headers.etag).toBe('"js-1"');
    expect(res.body).toBe("");
    expectAppCspPair(res.headers);
  });

  it("falls back to index.html for HTML-accepting misses (SPA deep links)", async () => {
    const res = await edge.app.inject({
      url: "/some/client/route",
      headers: { ...HOST, accept: "text/html,application/xhtml+xml" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("demo");
    expectAppCspPair(res.headers);
  });

  it("widens Report-Only img-src with EDGE_IMG_SRC_EXTRA", async () => {
    const local = buildTestEdge({ config: { imgSrcExtra: ["https://images.example"] } });
    local.blob.set(`${PREFIX}index.html`, {
      body: "<!doctype html><body>extra</body>",
      contentType: "text/html; charset=utf-8",
    });
    await local.app.ready();
    const res = await local.app.inject({ url: "/", headers: HOST });
    const enforced = res.headers["content-security-policy"] as string;
    const reportOnly = res.headers["content-security-policy-report-only"] as string;
    expect(reportOnly).toContain("https://images.example");
    expect(enforced).not.toContain("images.example");
    expect(enforced).not.toContain("images.example");
    const connect = enforced.split("; ").find((d) => d.startsWith("connect-src"));
    expect(connect).not.toContain("images.example");
    await local.app.close();
  });

  it("injects HTML with both CSP headers when fetch.shim is enabled", async () => {
    const shimApp = buildTestEdge({
      registry: new FakeRegistry([
        registryEntry({
          appId: APP_ID,
          slug: "demo",
          blobPrefix: PREFIX,
          fetch: { connections: new Map(), requestsPerDay: 0, shim: true },
        }),
      ]),
    });
    shimApp.blob.set(`${PREFIX}index.html`, {
      body: "<!doctype html><html><head></head><body>shim</body></html>",
      contentType: "text/html; charset=utf-8",
    });
    await shimApp.app.ready();
    const res = await shimApp.app.inject({ url: "/", headers: HOST });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("helix/fetch-shim.js");
    expectAppCspPair(res.headers);
    await shimApp.app.close();
  });

  it("hard-404s non-HTML misses", async () => {
    const res = await edge.app.inject({
      url: "/missing.js",
      headers: { ...HOST, accept: "*/*" },
    });
    expect(res.statusCode).toBe(404);
  });

  it("404s traversal attempts without composing a blob key", async () => {
    // `/..%2f` survives client-side URL normalization (unlike `/%2e%2e/`,
    // which browsers and light-my-request collapse before sending), so this
    // exercises the server-side rejection a raw-socket client would hit.
    const before = edge.blob.requests.length;
    const res = await edge.app.inject({ url: "/..%2fsecrets", headers: HOST });
    expect(res.statusCode).toBe(404);
    expect(edge.blob.requests.length).toBe(before); // never reached the blob
  });

  it("404s percent-encoded reserved-namespace paths instead of serving assets", async () => {
    // The asset handler percent-decodes, so `/_api%2fme` would otherwise
    // resolve the blob `_api/me` — the reserved check must see the decoded
    // path too. The bundle ships matching assets to prove they never serve.
    for (const url of ["/_api%2fme", "/%5fapi/me", "/_auth%2fcomplete"]) {
      const before = edge.blob.requests.length;
      const res = await edge.app.inject({ url, headers: HOST });
      expect(res.statusCode, url).toBe(404);
      expect(edge.blob.requests.length, url).toBe(before); // never reached the blob
    }
  });

  it("serves filenames containing `..` that are not traversal segments", async () => {
    const res = await edge.app.inject({ url: "/vendor..min.js", headers: HOST });
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe("//..");
    // And a missing one is a plain 404, not a 500 from the escape bug-trap.
    const missing = await edge.app.inject({
      url: "/foo..bar.js",
      headers: { ...HOST, accept: "*/*" },
    });
    expect(missing.statusCode).toBe(404);
  });

  it("405s non-GET/HEAD with Allow", async () => {
    const res = await edge.app.inject({ method: "POST", url: "/", headers: HOST });
    expect(res.statusCode).toBe(405);
    expect(res.headers.allow).toBe("GET, HEAD");
  });

  it("never serves the platform health JSON on an app host", async () => {
    const res = await edge.app.inject({ url: "/health", headers: { ...HOST, accept: "*/*" } });
    // No /health file in this bundle and a non-HTML accept → plain 404.
    expect(res.statusCode).toBe(404);
  });
});

describe("app hosts: registry states", () => {
  it("404s an unknown slug", async () => {
    const res = await edge.app.inject({
      url: "/",
      headers: { host: "nope.local.helix.azxlabs.io" },
    });
    expect(res.statusCode).toBe(404);
  });

  it("404s an app with no live version, identically to unknown", async () => {
    const { app } = buildTestEdge({
      registry: new FakeRegistry([registryEntry({ appId: APP_ID, slug: "fresh" })]),
    });
    const res = await app.inject({ url: "/", headers: { host: "fresh.local.helix.azxlabs.io" } });
    expect(res.statusCode).toBe(404);
    await app.close();
  });

  it("410s an archived app with Clear-Site-Data", async () => {
    const { app } = buildTestEdge({
      registry: new FakeRegistry([
        registryEntry({ appId: APP_ID, slug: "old", archived: true, blobPrefix: PREFIX }),
      ]),
    });
    const res = await app.inject({ url: "/", headers: { host: "old.local.helix.azxlabs.io" } });
    expect(res.statusCode).toBe(410);
    expect(res.headers["clear-site-data"]).toBe('"cache", "storage"');
    expect(res.headers["cache-control"]).toBe("no-store");
    await app.close();
  });

  it("503s app hosts until the first projection load", async () => {
    const { app } = buildTestEdge({ registry: new FakeRegistry([], { loaded: false }) });
    const res = await app.inject({ url: "/", headers: HOST });
    expect(res.statusCode).toBe(503);
    expect(res.headers["retry-after"]).toBe("5");
    // Platform health *reports* the registry but never fails the request: a
    // non-200 would let a liveness probe kill a replica that is serving
    // correctly from a stale copy (ADR-0025). A cold projection is `error`
    // because every app host is 503ing — this state used to read green.
    const health = await app.inject({ url: "/health", headers: { host: "localhost" } });
    expect(health.statusCode).toBe(200);
    expect(health.json().status).toBe("error");
    expect(health.json().checks[0].detail).toContain("never loaded");
    await app.close();
  });

  it("degrades /health on a stale projection, still 200, while apps keep serving", async () => {
    const registry = new FakeRegistry([
      registryEntry({ appId: APP_ID, slug: "demo", blobPrefix: PREFIX }),
    ]);
    const { app, blob } = buildTestEdge({ registry });
    blob.set(`${PREFIX}index.html`, { body: "<h1>stale but served</h1>" });

    // 6× the 60s reconcile interval: past the degrade line, short of the error one.
    registry.freshnessOverride = { staleForMs: 6 * 60_000, consecutiveLoadFailures: 6 };
    let health = await app.inject({ url: "/health", headers: { host: "localhost" } });
    expect(health.statusCode).toBe(200);
    expect(health.json()).toMatchObject({
      status: "degraded",
      checks: [
        { name: "registry-projection", status: "degraded" },
        // No forwarded traffic in this suite: the check stays "not enough yet".
        { name: "trust-proxy", status: "ok" },
      ],
    });
    expect(health.headers["cache-control"]).toBe("no-store");
    // The whole point of degrading rather than failing: apps still serve.
    const page = await app.inject({ url: "/", headers: HOST });
    expect(page.statusCode).toBe(200);

    // Past 20× the interval it's an error, and the counters ride along.
    registry.freshnessOverride = { staleForMs: 21 * 60_000, consecutiveLoadFailures: 21 };
    health = await app.inject({ url: "/health", headers: { host: "localhost" } });
    expect(health.statusCode).toBe(200);
    expect(health.json().status).toBe("error");
    expect(health.json().checks[0].metrics).toEqual({
      consecutiveLoadFailures: 21,
      staleForSeconds: 1260,
    });
    await app.close();
  });
});

describe("the M2 auth bypass flag", () => {
  it("fails closed: without the flag, app hosts 503 and /health still works", async () => {
    const { app } = buildTestEdge({ config: { allowUnauthenticated: false } });
    const res = await app.inject({ url: "/", headers: HOST });
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain("EDGE_DEV_ALLOW_UNAUTHENTICATED");
    const health = await app.inject({ url: "/health", headers: { host: "localhost" } });
    expect(health.statusCode).toBe(200);
    await app.close();
  });
});
