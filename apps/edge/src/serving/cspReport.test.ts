import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { ATTR_OUTCOME, INSTR_CSP_REPORTS, type CspReportOutcome } from "@azx-pbc/shared/telemetry";
import { InMemoryCounterStore } from "../gateway/counterStore.js";
import { CspReportInsertThrottle } from "./cspReportThrottle.js";
import { startRecordingTelemetry } from "@azx-pbc/telemetry/testing";
import { buildApp } from "../app.js";
import type { EdgeConfig } from "../config.js";
import { FakeBlobReader, FakeRegistry, registryEntry } from "../test/fakes.js";
import {
  extractReport,
  foldDirective,
  type CspReportRecord,
  type CspReportStore,
} from "./cspReport.js";
import { CSP_REPORT_DIRECTIVES } from "@azx-pbc/shared/telemetry";

const APP_ID = "11111111-1111-4111-8111-111111111111";

function testConfig(): EdgeConfig {
  return {
    baseDomain: "local.helix.azxlabs.io",
    controlDomain: "local.helix.azxlabs.io",
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
    legacyAppRedirect: false,
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
    imgSrcReportOnly: false,
    imgSrcAllowAll: false,
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
  };
}

class FakeCspReportStore implements CspReportStore {
  records: CspReportRecord[] = [];
  fail = false;
  async record(r: CspReportRecord): Promise<void> {
    if (this.fail) throw new Error("store down");
    this.records.push(r);
  }
  async close(): Promise<void> {}
}

describe("extractReport", () => {
  it("parses a legacy report-uri body", () => {
    expect(
      extractReport({
        "csp-report": {
          "effective-directive": "connect-src",
          "blocked-uri": "https://api.foo.com/x",
          "document-uri": "https://demo.local.helix.azxlabs.io/",
        },
      }),
    ).toEqual({
      directive: "connect-src",
      blockedUri: "https://api.foo.com/x",
      documentUri: "https://demo.local.helix.azxlabs.io/",
      disposition: "unknown",
    });
  });

  it("parses legacy disposition", () => {
    expect(
      extractReport({
        "csp-report": {
          "effective-directive": "img-src",
          "blocked-uri": "https://x.io/a.png",
          disposition: "report",
        },
      })?.disposition,
    ).toBe("report");
    expect(
      extractReport({
        "csp-report": {
          "effective-directive": "img-src",
          "blocked-uri": "https://x.io/a.png",
          disposition: "enforce",
        },
      })?.disposition,
    ).toBe("enforce");
    expect(
      extractReport({
        "csp-report": {
          "effective-directive": "img-src",
          "blocked-uri": "https://x.io/a.png",
          disposition: "bogus",
        },
      })?.disposition,
    ).toBe("unknown");
  });

  it("parses a Reporting-API array body", () => {
    expect(
      extractReport([
        {
          type: "csp-violation",
          body: { effectiveDirective: "img-src", blockedURL: "https://x.io/a.png" },
        },
      ]),
    ).toMatchObject({
      directive: "img-src",
      blockedUri: "https://x.io/a.png",
      disposition: "unknown",
    });
    expect(
      extractReport([
        {
          type: "csp-violation",
          body: {
            effectiveDirective: "img-src",
            blockedURL: "https://x.io/a.png",
            disposition: "report",
          },
        },
      ])?.disposition,
    ).toBe("report");
  });

  it("returns null when there is no blocked URL", () => {
    expect(extractReport({ "csp-report": {} })).toBeNull();
    expect(extractReport({})).toBeNull();
    expect(extractReport("garbage")).toBeNull();
  });
});

describe("foldDirective", () => {
  for (const name of CSP_REPORT_DIRECTIVES) {
    if (name === "other") continue;
    it(`folds ${name}`, () => {
      expect(foldDirective(name)).toBe(name);
    });
  }
  it("folds CSP3 sub-directives and hostile input", () => {
    expect(foldDirective("script-src-elem")).toBe("script-src");
    expect(foldDirective("IMG-SRC")).toBe("img-src");
    expect(foldDirective("img-src 'self'")).toBe("img-src");
    expect(foldDirective("default-src")).toBe("other");
    expect(foldDirective("")).toBe("other");
    expect(foldDirective("x".repeat(5000))).toBe("other");
  });
});

describe("POST /_csp-report", () => {
  let store: FakeCspReportStore;
  let edge: { app: FastifyInstance };

  beforeAll(async () => {
    store = new FakeCspReportStore();
    const registry = new FakeRegistry([
      registryEntry({ appId: APP_ID, slug: "demo", blobPrefix: `apps/${APP_ID}/1/` }),
    ]);
    const app = buildApp({
      config: testConfig(),
      registry,
      blob: new FakeBlobReader(),
      cspReports: store,
    });
    edge = { app };
    await app.ready();
  });

  afterAll(async () => {
    await edge.app.close();
  });

  it("records a reported violation and answers 204", async () => {
    const res = await edge.app.inject({
      method: "POST",
      url: "/_csp-report",
      headers: { host: "demo.local.helix.azxlabs.io", "content-type": "application/csp-report" },
      payload: JSON.stringify({
        "csp-report": {
          "effective-directive": "connect-src",
          "blocked-uri": "https://api.foo.com",
        },
      }),
    });
    expect(res.statusCode).toBe(204);
    expect(store.records).toEqual([
      {
        appId: APP_ID,
        directive: "connect-src",
        blockedUri: "https://api.foo.com",
        documentUri: null,
      },
    ]);
  });

  it("204s without recording when the report has nothing useful", async () => {
    store.records.length = 0;
    const res = await edge.app.inject({
      method: "POST",
      url: "/_csp-report",
      headers: { host: "demo.local.helix.azxlabs.io", "content-type": "application/csp-report" },
      payload: JSON.stringify({ "csp-report": {} }),
    });
    expect(res.statusCode).toBe(204);
    expect(store.records).toHaveLength(0);
  });

  it("404s for an unknown app", async () => {
    const res = await edge.app.inject({
      method: "POST",
      url: "/_csp-report",
      headers: { host: "nope.local.helix.azxlabs.io", "content-type": "application/csp-report" },
      payload: JSON.stringify({ "csp-report": { "blocked-uri": "https://x" } }),
    });
    expect(res.statusCode).toBe(404);
  });

  async function injectReport(
    app: FastifyInstance,
    payload: Record<string, unknown>,
  ): Promise<void> {
    await app.inject({
      method: "POST",
      url: "/_csp-report",
      headers: { host: "demo.local.helix.azxlabs.io", "content-type": "application/csp-report" },
      payload: JSON.stringify(payload),
    });
  }

  function buildMetricEdge(
    reportStore: FakeCspReportStore,
    insertThrottle: CspReportInsertThrottle | null = null,
  ): FastifyInstance {
    const registry = new FakeRegistry([
      registryEntry({ appId: APP_ID, slug: "demo", blobPrefix: `apps/${APP_ID}/1/` }),
    ]);
    return buildApp({
      config: testConfig(),
      registry,
      blob: new FakeBlobReader(),
      cspReports: reportStore,
      cspReportInsertThrottle: insertThrottle,
    });
  }

  it("increments the counter with bounded dimensions", async () => {
    const recording = startRecordingTelemetry();
    const localStore = new FakeCspReportStore();
    const app = buildMetricEdge(localStore);
    await app.ready();
    await injectReport(app, {
      "csp-report": {
        "effective-directive": "img-src",
        "blocked-uri": "https://x.io/a.png",
        disposition: "report",
      },
    });
    await app.close();
    const points = await recording.metrics();
    const hit = points.find((p) => p.name === INSTR_CSP_REPORTS);
    expect(hit?.value).toBe(1);
    expect(Object.keys(hit?.attributes ?? {}).sort()).toEqual([
      "helix.app_id",
      "helix.csp.directive",
      "helix.csp.disposition",
      "helix.outcome",
    ]);
    expect(hit?.attributes[ATTR_OUTCOME]).toBe("recorded");
    expect(hit?.attributes["helix.csp.directive"]).toBe("img-src");
    expect(hit?.attributes["helix.csp.disposition"]).toBe("report");
    await recording.restore();
  });

  it("folds a hostile directive to other", async () => {
    const recording = startRecordingTelemetry();
    const localStore = new FakeCspReportStore();
    const app = buildMetricEdge(localStore);
    await app.ready();
    await injectReport(app, {
      "csp-report": {
        "effective-directive": "app-chosen-directive",
        "blocked-uri": "https://x.io/a.png",
      },
    });
    await app.close();
    const points = await recording.metrics();
    const hit = points.find((p) => p.name === INSTR_CSP_REPORTS);
    expect(hit?.attributes["helix.csp.directive"]).toBe("other");
    await recording.restore();
  });

  it("counts before insert when the store throws", async () => {
    const recording = startRecordingTelemetry();
    const localStore = new FakeCspReportStore();
    localStore.fail = true;
    const app = buildMetricEdge(localStore);
    await app.ready();
    const res = await app.inject({
      method: "POST",
      url: "/_csp-report",
      headers: { host: "demo.local.helix.azxlabs.io", "content-type": "application/csp-report" },
      payload: JSON.stringify({
        "csp-report": {
          "effective-directive": "connect-src",
          "blocked-uri": "https://api.foo.com",
        },
      }),
    });
    await app.close();
    expect(res.statusCode).toBe(204);
    const points = await recording.metrics();
    expect(points.filter((p) => p.name === INSTR_CSP_REPORTS).length).toBeGreaterThan(0);
    await recording.restore();
  });

  it("does not count a report with no blocked-uri", async () => {
    const recording = startRecordingTelemetry();
    const app = buildMetricEdge(new FakeCspReportStore());
    await app.ready();
    await injectReport(app, { "csp-report": { "effective-directive": "img-src" } });
    await app.close();
    const points = await recording.metrics();
    expect(points.filter((p) => p.name === INSTR_CSP_REPORTS)).toHaveLength(0);
    await recording.restore();
  });

  it.each([
    ["recorded", { fail: false, overCap: false }, "recorded"],
    ["dropped", { fail: false, overCap: true }, "dropped"],
    ["failed", { fail: true, overCap: false }, "failed"],
  ] as const)(
    "sets helix.outcome to %s on the counter",
    async (_label, opts, expected: CspReportOutcome) => {
      const recording = startRecordingTelemetry();
      const localStore = new FakeCspReportStore();
      localStore.fail = opts.fail;
      const throttle = opts.overCap
        ? new CspReportInsertThrottle(new InMemoryCounterStore(), { max: 0, windowMs: 60_000 })
        : null;
      const app = buildMetricEdge(localStore, throttle);
      await app.ready();
      await injectReport(app, {
        "csp-report": {
          "effective-directive": "img-src",
          "blocked-uri": "https://x.io/a.png",
        },
      });
      await app.close();
      const hit = (await recording.metrics()).find((p) => p.name === INSTR_CSP_REPORTS);
      expect(hit?.attributes[ATTR_OUTCOME]).toBe(expected);
      await recording.restore();
    },
  );

  it("does not count on unknown slug", async () => {
    const recording = startRecordingTelemetry();
    const app = buildMetricEdge(new FakeCspReportStore());
    await app.ready();
    await app.inject({
      method: "POST",
      url: "/_csp-report",
      headers: { host: "nope.local.helix.azxlabs.io", "content-type": "application/csp-report" },
      payload: JSON.stringify({
        "csp-report": { "effective-directive": "img-src", "blocked-uri": "https://x" },
      }),
    });
    await app.close();
    const points = await recording.metrics();
    expect(points.filter((p) => p.name === INSTR_CSP_REPORTS)).toHaveLength(0);
    await recording.restore();
  });
});
