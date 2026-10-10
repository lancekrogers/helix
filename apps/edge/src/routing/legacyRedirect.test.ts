import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { INSTR_LEGACY_APP_REDIRECTS, LEGACY_REDIRECT_OUTCOMES } from "@azx-pbc/shared/telemetry";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import type { FastifyRequest } from "fastify";
import { buildApp } from "../app.js";
import { publicOrigin } from "../config.js";
import { decideLegacyRedirect } from "./legacyRedirect.js";
import { SPLIT_CONTROL_DOMAIN, splitEdgeConfig } from "../test/config.js";
import { FakeBlobReader, FakeRegistry, registryEntry } from "../test/fakes.js";

const APP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PREFIX = "apps/demo/1/";
const SLUG = "demo";
const LEGACY_HOST = `${SLUG}.${SPLIT_CONTROL_DOMAIN}`;
const EXPECTED_ORIGIN = publicOrigin(splitEdgeConfig({ legacyAppRedirect: true }), SLUG);

function buildRedirectEdge(
  registry: FakeRegistry,
  configOverrides: Parameters<typeof splitEdgeConfig>[0] = {},
) {
  return buildApp({
    config: splitEdgeConfig({ legacyAppRedirect: true, ...configOverrides }),
    registry,
    blob: new FakeBlobReader(),
  });
}

async function injectLegacyHost(
  app: FastifyInstance,
  opts: {
    method?: "GET" | "HEAD" | "POST" | "PUT" | "DELETE";
    url: string;
    headers?: Record<string, string>;
  },
) {
  return app.inject({
    method: opts.method ?? "GET",
    url: opts.url,
    headers: { host: LEGACY_HOST, ...opts.headers },
  });
}

describe("legacy app host redirect", () => {
  let recording: RecordingTelemetry | undefined;

  afterEach(async () => {
    await recording?.restore();
    recording = undefined;
  });

  it("redirects GET and HEAD with no-store, no-referrer, and apps origin Location", async () => {
    const app = buildRedirectEdge(
      new FakeRegistry([registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: PREFIX })]),
    );
    for (const method of ["GET", "HEAD"] as const) {
      for (const url of ["/page?x=1", "/", "/health"]) {
        const res = await injectLegacyHost(app, { method, url });
        expect(res.statusCode).toBe(307);
        expect(res.headers.location).toBe(`${EXPECTED_ORIGIN}${url}`);
        expect(res.headers["cache-control"]).toBe("no-store");
        expect(res.headers["referrer-policy"]).toBe("no-referrer");
      }
    }
    await app.close();
  });

  it("refuses non-GET/HEAD with 404 and refused_path", async () => {
    recording = startRecordingTelemetry();
    const app = buildRedirectEdge(
      new FakeRegistry([registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: PREFIX })]),
    );
    for (const method of ["POST", "PUT", "DELETE"] as const) {
      const res = await injectLegacyHost(app, { method, url: "/page" });
      expect(res.statusCode).toBe(404);
      expect(res.body).toBe("Not found\n");
    }
    const points = await recording.metrics();
    const refused = points
      .filter(
        (p) =>
          p.name === INSTR_LEGACY_APP_REDIRECTS && p.attributes["helix.outcome"] === "refused_path",
      )
      .reduce((sum, p) => sum + p.value, 0);
    expect(refused).toBe(3);
    await app.close();
  });

  it.each([
    "/_auth/complete?token=x",
    "/_api/me",
    "/_helix/sw.js",
    "/_csp-report",
    "/_anything",
    "/%5Fapi/me",
    "/a%0d%0ab",
  ])("refuses reserved path %s", async (url) => {
    recording = startRecordingTelemetry();
    const app = buildRedirectEdge(
      new FakeRegistry([registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: PREFIX })]),
    );
    const res = await injectLegacyHost(app, { url });
    expect(res.statusCode).toBe(404);
    await app.close();
  });

  it("refuses encoded slash paths that would become /_api after decode", () => {
    const registry = new FakeRegistry([
      registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: PREFIX }),
    ]);
    const config = splitEdgeConfig({ legacyAppRedirect: true });
    const req = { method: "GET", raw: { url: "/_api%2fme" } } as FastifyRequest;
    expect(decideLegacyRedirect(req, SLUG, { config, registry }).kind).toBe("refused_path");
    const networkPath = { method: "GET", raw: { url: "//evil.example/x" } } as FastifyRequest;
    expect(decideLegacyRedirect(networkPath, SLUG, { config, registry }).kind).toBe("refused_path");
    const backslash = { method: "GET", raw: { url: "/\\evil.example" } } as FastifyRequest;
    expect(decideLegacyRedirect(backslash, SLUG, { config, registry }).kind).toBe("refused_path");
  });

  it.each(["/%2F_api/me", "/%2f_auth/complete?token=x"])(
    "refuses normalized first-segment reserved path %s",
    (url) => {
      const registry = new FakeRegistry([
        registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: PREFIX }),
      ]);
      const config = splitEdgeConfig({ legacyAppRedirect: true });
      const req = { method: "GET", raw: { url } } as FastifyRequest;
      expect(decideLegacyRedirect(req, SLUG, { config, registry }).kind).toBe("refused_path");
    },
  );

  it("answers unknown_app cases with identical 404 bodies", async () => {
    recording = startRecordingTelemetry();
    const bodies: string[] = [];
    const cases: { registry: FakeRegistry; config?: Parameters<typeof splitEdgeConfig>[0] }[] = [
      { registry: new FakeRegistry([]) },
      { registry: new FakeRegistry([registryEntry({ slug: "missing", blobPrefix: PREFIX })]) },
      {
        registry: new FakeRegistry([
          registryEntry({ slug: SLUG, blobPrefix: PREFIX, archived: true }),
        ]),
      },
      { registry: new FakeRegistry([registryEntry({ slug: SLUG, blobPrefix: null })]) },
      {
        registry: new FakeRegistry([
          registryEntry({ slug: SLUG, blobPrefix: PREFIX, visibilityMode: "public" }),
        ]),
        config: { allowPublicApps: false },
      },
      {
        registry: new FakeRegistry([registryEntry({ slug: SLUG, blobPrefix: PREFIX })], {
          loaded: false,
        }),
      },
    ];
    for (const { registry, config } of cases) {
      const app = buildRedirectEdge(registry, config);
      const res = await injectLegacyHost(app, { url: "/" });
      expect(res.statusCode).toBe(404);
      bodies.push(res.body);
      await app.close();
    }
    expect(new Set(bodies).size).toBe(1);
    expect(bodies[0]).toBe("Not found\n");
    const points = await recording.metrics();
    const unknown = points
      .filter(
        (p) =>
          p.name === INSTR_LEGACY_APP_REDIRECTS && p.attributes["helix.outcome"] === "unknown_app",
      )
      .reduce((sum, p) => sum + p.value, 0);
    expect(unknown).toBe(cases.length);
  });

  it("/health on a legacy host redirects instead of platform health JSON", async () => {
    const app = buildRedirectEdge(
      new FakeRegistry([registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: PREFIX })]),
    );
    const res = await injectLegacyHost(app, { url: "/health" });
    expect(res.statusCode).toBe(307);
    expect(res.headers.location).toBe(`${EXPECTED_ORIGIN}/health`);
    expect(res.body).not.toContain('"service"');
    await app.close();
  });

  it("ignores hostile forwarded host and Origin when building Location", async () => {
    const app = buildRedirectEdge(
      new FakeRegistry([registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: PREFIX })]),
    );
    const res = await injectLegacyHost(app, {
      url: "/page",
      headers: {
        "x-forwarded-host": "evil.example",
        origin: "https://evil.example",
      },
    });
    expect(res.headers.location).toBe(`${EXPECTED_ORIGIN}/page`);
    await app.close();
  });

  it("does nothing when legacyAppRedirect is off", async () => {
    recording = startRecordingTelemetry();
    const app = buildApp({
      config: splitEdgeConfig({ legacyAppRedirect: false }),
      registry: new FakeRegistry([
        registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: PREFIX }),
      ]),
      blob: new FakeBlobReader(),
    });
    const res = await injectLegacyHost(app, { url: "/page" });
    expect(res.statusCode).toBe(404);
    const points = await recording.metrics();
    expect(points.some((p) => p.name === INSTR_LEGACY_APP_REDIRECTS)).toBe(false);
    await app.close();
  });

  it("records bounded counter dimensions", async () => {
    recording = startRecordingTelemetry();
    const app = buildRedirectEdge(
      new FakeRegistry([registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: PREFIX })]),
    );
    await injectLegacyHost(app, { url: "/" });
    await injectLegacyHost(app, {
      url: "/nope",
      headers: { host: `ghost.${SPLIT_CONTROL_DOMAIN}` },
    });
    const points = await recording.metrics();
    const legacyPoints = points.filter((p) => p.name === INSTR_LEGACY_APP_REDIRECTS);
    expect(legacyPoints.length).toBeGreaterThanOrEqual(2);
    for (const point of legacyPoints) {
      expect(Object.keys(point.attributes).sort()).toEqual(["helix.outcome"]);
      expect(LEGACY_REDIRECT_OUTCOMES).toContain(point.attributes["helix.outcome"]);
    }
    await app.close();
  });
});
