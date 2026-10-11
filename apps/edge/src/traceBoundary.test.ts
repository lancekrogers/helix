import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { hashDevToken } from "@azx-pbc/shared/devToken";
import {
  context,
  defaultTextMapGetter,
  propagation,
  ROOT_CONTEXT,
  trace,
} from "@opentelemetry/api";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import { propagatorFor } from "@azx-pbc/telemetry";
import { REQUEST_HEADER_SAFELIST } from "@azx-pbc/shared";
import {
  SPAN_CONNECTIONS_PROXY,
  SPAN_CONSENT_START,
  SPAN_CONSENT_START_DEV,
  SPAN_CONSENT_STATUS_EDGE,
  SPAN_LEGACY_APP_REDIRECT,
} from "@azx-pbc/shared/telemetry";
import { withRootSpan } from "./telemetry.js";
import { buildApp } from "./app.js";
import { buildDevGateway } from "./devGateway/app.js";
import type { DevTokenStore } from "./devGateway/devTokenStore.js";
import {
  SPLIT_CONTROL_DOMAIN,
  splitEdgeConfig,
  testAuthConfig,
  testDevGatewayConfig,
  testEdgeConfig,
} from "./test/config.js";
import {
  FakeBlobReader,
  FakeOidcClient,
  FakePortalProvider,
  FakeRegistry,
  FakeSessionStore,
  registryEntry,
} from "./test/fakes.js";

/**
 * ADR-0037 decision 7, end to end: propagation runs **inward only**.
 *
 * The edge starts a fresh root for every app-user request and never continues
 * the caller's trace; it injects outward on the edge → egress hop, where the
 * request's authority already comes from the signed attested instruction, and
 * egress extracts there and only there.
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

const APP_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";
const APP_SPAN_ID = "00f067aa0ba902b7";
const APP_TRACEPARENT = `00-${APP_TRACE_ID}-${APP_SPAN_ID}-01`;

describe("an app-user request never joins the caller's trace", () => {
  it("starts a fresh root even when a valid traceparent is supplied", async () => {
    // Simulate the inbound side as the edge is configured: an inject-only
    // propagator installed globally, then a handler span.
    propagation.setGlobalPropagator(propagatorFor("inject-only"));
    const inbound = propagation.extract(
      ROOT_CONTEXT,
      { traceparent: APP_TRACEPARENT, tracestate: "vendor=app-chosen" },
      defaultTextMapGetter,
    );

    await context.with(inbound, () => withRootSpan("helix.gateway.fetch", {}, async () => {}));

    const span = recording.spans()[0];
    expect(span?.spanContext().traceId).not.toBe(APP_TRACE_ID);
    expect(span?.parentSpanContext).toBeUndefined();
  });

  it("records nothing from the app's trace headers", async () => {
    propagation.setGlobalPropagator(propagatorFor("inject-only"));
    await withRootSpan("helix.gateway.fetch", {}, async () => {});

    // Project before serialising: a ReadableSpan holds a back-reference to its
    // processor and exporter, so it is circular.
    const dump = JSON.stringify(
      recording.spans().map((sp) => ({ ...sp.attributes, ...sp.spanContext() })),
    );
    expect(dump).not.toContain(APP_TRACE_ID);
    expect(dump).not.toContain("vendor=app-chosen");
  });
});

describe("the edge → egress hop is one trace", () => {
  it("injects the edge's own trace id, and egress adopts it as the parent", async () => {
    propagation.setGlobalPropagator(propagatorFor("inject-only"));

    // Edge side: a root span, then inject as `HttpEgressProvider.proxy` does.
    const carrier: Record<string, string> = {};
    let edgeTraceId = "";
    let edgeSpanId = "";
    await withRootSpan("helix.gateway.fetch", {}, async () => {
      const active = trace.getActiveSpan()!.spanContext();
      edgeTraceId = active.traceId;
      edgeSpanId = active.spanId;
      propagation.inject(context.active(), carrier);
    });

    expect(carrier.traceparent).toContain(edgeTraceId);

    // Egress side: `full` propagation, so the header becomes the parent.
    const extracted = propagatorFor("full").extract(ROOT_CONTEXT, carrier, defaultTextMapGetter);
    const parent = trace.getSpanContext(extracted);
    expect(parent?.traceId).toBe(edgeTraceId);
    expect(parent?.spanId).toBe(edgeSpanId);
  });

  it("never forwards traceparent to a third-party upstream", async () => {
    // Egress's `safeRequestHeaders` forwards only this list. `traceparent` is a
    // platform correlation value and is nobody else's business — one word away
    // from regressing.
    expect(REQUEST_HEADER_SAFELIST).not.toContain("traceparent");
    expect(REQUEST_HEADER_SAFELIST).not.toContain("tracestate");
  });
});

describe("the /connections/* proxy route is a fresh root too", () => {
  /**
   * Driven through the real route: the callback URL is where a vendor's
   * redirect lands, so an inbound `traceparent` on it is exactly as
   * untrustworthy as on any app host — the proxy's root span must not adopt
   * it, and the portal-ward hop must inject the edge's own context.
   */
  it("an inbound traceparent never parents the route span", async () => {
    propagation.setGlobalPropagator(propagatorFor("inject-only"));
    const app: FastifyInstance = buildApp({
      config: testEdgeConfig({ auth: testAuthConfig(), internalSecret: Buffer.alloc(32, 7) }),
      registry: new FakeRegistry([
        registryEntry({
          appId: "11111111-1111-4111-8111-111111111111",
          slug: "demo",
          blobPrefix: "apps/a/1/",
        }),
      ]),
      blob: new FakeBlobReader(),
      sessions: new FakeSessionStore(),
      oidc: new FakeOidcClient(),
      portal: new FakePortalProvider(),
    });
    const res = await app.inject({
      method: "GET",
      url: "/connections/callback?code=x&state=y",
      headers: {
        host: "auth.local.helix.azxlabs.io",
        traceparent: APP_TRACEPARENT,
        tracestate: "vendor=app-chosen",
      },
    });
    expect(res.statusCode).toBe(200);
    await app.close();

    const span = recording.spans().find((sp) => sp.name === SPAN_CONNECTIONS_PROXY);
    expect(span).toBeDefined();
    expect(span?.spanContext().traceId).not.toBe(APP_TRACE_ID);
    expect(span?.parentSpanContext).toBeUndefined();
  });
});

describe("the consent start route is a fresh root too", () => {
  /**
   * The start route is a plain app-host navigation — an untrusted opener can
   * plant a `traceparent` on it as easily as on a gateway call, and the route
   * must open its own trace regardless.
   */
  it("an inbound traceparent never parents the route span", async () => {
    propagation.setGlobalPropagator(propagatorFor("inject-only"));
    const app: FastifyInstance = buildApp({
      config: testEdgeConfig({ auth: testAuthConfig(), internalSecret: Buffer.alloc(32, 7) }),
      registry: new FakeRegistry([
        registryEntry({
          appId: "22222222-2222-4222-8222-222222222222",
          slug: "demo",
          blobPrefix: "apps/a/1/",
        }),
      ]),
      blob: new FakeBlobReader(),
      sessions: new FakeSessionStore(),
      oidc: new FakeOidcClient(),
      portal: new FakePortalProvider(),
    });
    const res = await app.inject({
      method: "GET",
      url: "/_api/connections/asana/start?attempt=x",
      headers: {
        host: "demo.local.helix.azxlabs.io",
        traceparent: APP_TRACEPARENT,
        tracestate: "vendor=app-chosen",
      },
    });
    // The navigation guard refuses this one (no same-origin headers beyond the
    // trace headers) — the span fires anyway, and that is the span under test.
    expect(res.statusCode).toBe(403);
    await app.close();

    const span = recording.spans().find((sp) => sp.name === SPAN_CONSENT_START);
    expect(span).toBeDefined();
    expect(span?.spanContext().traceId).not.toBe(APP_TRACE_ID);
    expect(span?.parentSpanContext).toBeUndefined();
    // And nothing from the app's trace headers lands anywhere.
    const dump = JSON.stringify(
      recording.spans().map((sp) => ({ ...sp.attributes, ...sp.spanContext() })),
    );
    expect(dump).not.toContain(APP_TRACE_ID);
    expect(dump).not.toContain("vendor=app-chosen");
  });
});

describe("the dev-gateway consent start route is a fresh root too", () => {
  /**
   * The dev tier's POST comes from a foreign-origin dev app — the same
   * untrusted caller class, so an inbound `traceparent` is exactly as
   * untrustworthy there. The dev-gateway is inject-only by default
   * (`devGateway/server.ts`), and the route's span must show it.
   */
  it("an inbound traceparent never parents the route span", async () => {
    propagation.setGlobalPropagator(propagatorFor("inject-only"));
    const tokens: DevTokenStore = {
      async resolve(tokenHash) {
        return tokenHash === hashDevToken("PLANTED-DEV-BEARER")
          ? {
              appId: "33333333-3333-4333-8333-333333333333",
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
    portal.body = JSON.stringify({
      outcome: "started",
      authorizeUrl: "https://vendor.example/authorize",
    });
    const app: FastifyInstance = buildDevGateway({
      config: testDevGatewayConfig({ internalSecret: Buffer.alloc(32, 7) }),
      registry: new FakeRegistry([
        registryEntry({
          appId: "33333333-3333-4333-8333-333333333333",
          slug: "myapp",
          blobPrefix: "apps/a/1/",
        }),
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
      method: "POST",
      url: "/myapp/_api/connections/asana/start",
      headers: {
        host: "dev-api.local.helix.azxlabs.io",
        authorization: "Bearer PLANTED-DEV-BEARER",
        origin: "https://myapp.lovable.app",
        traceparent: APP_TRACEPARENT,
        tracestate: "vendor=app-chosen",
      },
    });
    expect(res.statusCode).toBe(200);
    await app.close();

    const span = recording.spans().find((sp) => sp.name === SPAN_CONSENT_START_DEV);
    expect(span).toBeDefined();
    expect(span?.spanContext().traceId).not.toBe(APP_TRACE_ID);
    expect(span?.parentSpanContext).toBeUndefined();
    const dump = JSON.stringify(
      recording.spans().map((sp) => ({ ...sp.attributes, ...sp.spanContext() })),
    );
    expect(dump).not.toContain(APP_TRACE_ID);
    expect(dump).not.toContain("vendor=app-chosen");
  });
});

describe("the connection-status route is a fresh root too (ADR-0031 as amended)", () => {
  /**
   * A plain app-host JSON read — an untrusted caller can plant a
   * `traceparent` on it as easily as on the consent start route.
   */
  it("an inbound traceparent never parents the route span", async () => {
    propagation.setGlobalPropagator(propagatorFor("inject-only"));
    const app: FastifyInstance = buildApp({
      config: testEdgeConfig({ auth: testAuthConfig(), internalSecret: Buffer.alloc(32, 7) }),
      registry: new FakeRegistry([
        registryEntry({
          appId: "22222222-2222-4222-8222-222222222222",
          slug: "demo",
          blobPrefix: "apps/a/1/",
        }),
      ]),
      blob: new FakeBlobReader(),
      sessions: new FakeSessionStore(),
      oidc: new FakeOidcClient(),
      portal: new FakePortalProvider(),
    });
    const res = await app.inject({
      method: "GET",
      url: "/_api/connections/asana/status",
      headers: {
        host: "demo.local.helix.azxlabs.io",
        traceparent: APP_TRACEPARENT,
        tracestate: "vendor=app-chosen",
      },
    });
    // The session gate refuses this one (401) — the span fires anyway, and
    // that is the span under test.
    expect(res.statusCode).toBe(401);
    await app.close();

    const span = recording.spans().find((sp) => sp.name === SPAN_CONSENT_STATUS_EDGE);
    expect(span).toBeDefined();
    expect(span?.spanContext().traceId).not.toBe(APP_TRACE_ID);
    expect(span?.parentSpanContext).toBeUndefined();
    const dump = JSON.stringify(
      recording.spans().map((sp) => ({ ...sp.attributes, ...sp.spanContext() })),
    );
    expect(dump).not.toContain(APP_TRACE_ID);
    expect(dump).not.toContain("vendor=app-chosen");
  });
});

describe("the legacy app host redirect is a fresh root too", () => {
  it("an inbound traceparent never parents the route span", async () => {
    propagation.setGlobalPropagator(propagatorFor("inject-only"));
    const app: FastifyInstance = buildApp({
      config: splitEdgeConfig({ legacyAppRedirect: true }),
      registry: new FakeRegistry([
        registryEntry({
          appId: "22222222-2222-4222-8222-222222222222",
          slug: "planted-slug",
          blobPrefix: "apps/a/1/",
        }),
      ]),
      blob: new FakeBlobReader(),
    });
    const res = await app.inject({
      method: "GET",
      url: "/page?token=PLANTED-QUERY-SECRET&code=PLANTED-CODE",
      headers: {
        host: `planted-slug.${SPLIT_CONTROL_DOMAIN}`,
        traceparent: APP_TRACEPARENT,
        tracestate: "vendor=app-chosen",
      },
    });
    expect(res.statusCode).toBe(307);
    await app.close();

    const span = recording.spans().find((sp) => sp.name === SPAN_LEGACY_APP_REDIRECT);
    expect(span).toBeDefined();
    expect(span?.spanContext().traceId).not.toBe(APP_TRACE_ID);
    expect(span?.parentSpanContext).toBeUndefined();
  });
});

describe("POST /_csp-report", () => {
  it("never continues an inbound traceparent", async () => {
    recording.reset();
    const app: FastifyInstance = buildApp({
      config: testEdgeConfig({ allowUnauthenticated: true }),
      registry: new FakeRegistry([
        registryEntry({
          appId: "22222222-2222-4222-8222-222222222222",
          slug: "demo",
          blobPrefix: "apps/a/1/",
        }),
      ]),
      blob: new FakeBlobReader(),
    });
    await app.inject({
      method: "POST",
      url: "/_csp-report",
      headers: {
        host: "demo.local.helix.azxlabs.io",
        traceparent: APP_TRACEPARENT,
        tracestate: "vendor=app-chosen",
        "content-type": "application/csp-report",
      },
      payload: JSON.stringify({
        "csp-report": {
          "effective-directive": "img-src",
          "blocked-uri": "https://x.example/p.png",
        },
      }),
    });
    await app.close();
    for (const span of recording.spans()) {
      expect(span.spanContext().traceId).not.toBe(APP_TRACE_ID);
    }
    const dump = JSON.stringify(recording.spans().map((s) => s.attributes));
    expect(dump).not.toContain(APP_TRACE_ID);
  });
});
