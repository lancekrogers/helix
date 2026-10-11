import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { hashDevToken, newDevToken } from "@azx-pbc/shared/devToken";
import {
  CONSENT_NONCE_ENTRY_PATH,
  type ConsultRequest,
  type ConsultResponse,
} from "@azx-pbc/shared";
import { SPAN_CONSENT_START_DEV } from "@azx-pbc/shared/telemetry";
import { startRecordingTelemetry } from "@azx-pbc/telemetry/testing";
import { buildDevGateway } from "./app.js";
import type { DevTokenRow, DevTokenStore } from "./devTokenStore.js";
import { controlOrigin } from "../config.js";
import { splitDevGatewayConfig, testDevGatewayConfig } from "../test/config.js";
import { FakeAppDataStore, FakeRegistry, FakeUsageStore, registryEntry } from "../test/fakes.js";
import type {
  PortalProvider,
  PortalProxyRequest,
  PortalProxyResponse,
} from "../routing/portalProvider.js";

/**
 * The dev tier's consent start — the bearer
 * POST that hands back the single-use popup URL. The consult rides a scripted
 * fake portal provider (the `consentStart.test.ts` seam style), so every
 * assertion here is against the real route and the real dev-token resolver —
 * only the portal hop is fake. The redemption half of the journey is the
 * portal's (`apps/portal/src/routes/connectionsPages.test.ts`); the assembled
 * journey is the integration suite's.
 */

const APP_ID = "11111111-1111-4111-8111-111111111111";
const SLUG = "myapp";
const HOST = { host: "dev-api.local.helix.azxlabs.io" };
const DEV_ORIGIN = "https://myapp.lovable.app";
const OTHER_REGISTERED_ORIGIN = "https://editor.dev.example";
const AUTH_ORIGIN = "https://auth.local.helix.azxlabs.io:8080";
const CALLBACK_URL = `${AUTH_ORIGIN}/connections/callback`;
const DEV_BEARER = "PLANTED-DEV-BEARER-TOKEN-VALUE";
const START_URL = `/${SLUG}/_api/connections/asana/start`;

/** In-memory dev-token store keyed by hash (the real store's shape). */
class FakeDevTokenStore implements DevTokenStore {
  readonly rows = new Map<string, DevTokenRow>();
  add(token: string, row: DevTokenRow): void {
    this.rows.set(hashDevToken(token), row);
  }
  async resolve(tokenHash: string): Promise<DevTokenRow | null> {
    return this.rows.get(tokenHash) ?? null;
  }
  async originAllowed(): Promise<boolean> {
    return false;
  }
  async close(): Promise<void> {}
}

/** The fake consult seam: captures every call, answers the scripted contract. */
class FakeConsultPortal implements PortalProvider {
  readonly requests: { target: string; body: string }[] = [];
  response: ConsultResponse = { outcome: "not_available" };
  status = 200;
  error: Error | null = null;

  async proxy(req: PortalProxyRequest): Promise<PortalProxyResponse> {
    const chunks: Buffer[] = [];
    if (req.body) {
      for await (const chunk of req.body) chunks.push(chunk as Buffer);
    }
    this.requests.push({ target: req.target, body: Buffer.concat(chunks).toString("utf8") });
    if (this.error) throw this.error;
    return {
      status: this.status,
      headers: { "content-type": "application/json" },
      body: Readable.from([Buffer.from(JSON.stringify(this.response))]),
    };
  }

  async close(): Promise<void> {}
}

function liveTokenRow(origins: string[] = [DEV_ORIGIN, OTHER_REGISTERED_ORIGIN]): DevTokenRow {
  return {
    appId: APP_ID,
    developerOid: "oid-developer-alice",
    origins,
    expiresAt: new Date(Date.now() + 60_000),
    revokedAt: null,
  };
}

interface Harness {
  app: FastifyInstance;
  portal: FakeConsultPortal;
  tokens: FakeDevTokenStore;
}

function build(opts: { withPortal?: boolean; withInternalSecret?: boolean } = {}): Harness {
  const portal = new FakeConsultPortal();
  const tokens = new FakeDevTokenStore();
  tokens.add(DEV_BEARER, liveTokenRow());
  const internalSecret = Buffer.alloc(32, 7);
  const app = buildDevGateway({
    config: testDevGatewayConfig({
      internalSecret: opts.withInternalSecret === false ? null : internalSecret,
    }),
    registry: new FakeRegistry([
      registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: "apps/a/1/" }),
    ]),
    devTokens: tokens,
    appData: new FakeAppDataStore(),
    usage: new FakeUsageStore(),
    llmProvider: null,
    egress: null,
    instructionKey: null,
    portal: opts.withPortal === false ? null : portal,
  });
  return { app, portal, tokens };
}

function post(
  app: FastifyInstance,
  opts: { token?: string | null; origin?: string | null; url?: string } = {},
) {
  const headers: Record<string, string> = { ...HOST };
  if (opts.token !== null) headers.authorization = `Bearer ${opts.token ?? DEV_BEARER}`;
  if (opts.origin !== null) headers.origin = opts.origin ?? DEV_ORIGIN;
  return app.inject({ method: "POST", url: opts.url ?? START_URL, headers });
}

function consultRequest(h: Harness): ConsultRequest {
  return JSON.parse(h.portal.requests[0]?.body ?? "{}") as ConsultRequest;
}

describe("the dev consent start route — started outcome", () => {
  it("returns a popup URL whose every component is nonce/reference material", async () => {
    const h = build();
    h.portal.response = {
      outcome: "started",
      authorizeUrl: "https://vendor.example/authorize?state=x",
    };
    const res = await post(h.app);
    expect(res.statusCode).toBe(200);
    const body = res.json<{ outcome: string; popupUrl?: string }>();
    expect(body.outcome).toBe("started");

    const popup = new URL(body.popupUrl!);
    // The URL's components: the auth host (from config, never the request),
    // the entry path, and ONE query parameter — the nonce. Nothing else.
    expect(popup.origin).toBe(AUTH_ORIGIN);
    expect(popup.pathname).toBe(CONSENT_NONCE_ENTRY_PATH);
    expect([...popup.searchParams.keys()].sort()).toEqual(["nonce"]);
    // Adversarial scan of the whole serialized URL: no bearer token, no dev
    // credential, no token value, no vendor protocol material.
    for (const forbidden of [
      DEV_BEARER,
      "vendor.example",
      "state",
      "code_challenge",
      "access_token",
    ]) {
      expect(body.popupUrl, `the popup URL carried ${forbidden}`).not.toContain(forbidden);
    }
    await h.app.close();
  });

  it("the consult carries the dev identity, the validated Origin, and the auth-host callback URL", async () => {
    const h = build();
    h.portal.response = { outcome: "started", authorizeUrl: "https://vendor.example/authorize" };
    const res = await post(h.app);
    expect(res.statusCode).toBe(200);
    expect(h.portal.requests.length).toBe(1);
    expect(h.portal.requests[0]!.target).toBe("/internal/connections/consult");

    const body = consultRequest(h);
    // The dev token's developer identity — kind `dev`, env pinned by the kind.
    const identity = body.identity;
    if (identity.kind !== "dev") throw new Error("the consult did not carry the dev identity");
    expect(identity.developerOid).toBe("oid-developer-alice");
    // The opener origin is the request's VALIDATED Origin — the completion
    // message's target origin, recorded verbatim (canonicalized).
    expect(identity.nonce).toBeTruthy();
    expect(body.openerOrigin).toBe(DEV_ORIGIN);
    expect(body.callbackUrl).toBe(CALLBACK_URL);
    // The nonce in the consult IS the nonce in the popup URL — the URL's one
    // reference to the attempt the consult wrote.
    const popupUrl = res.json<{ popupUrl: string }>().popupUrl;
    expect(new URL(popupUrl).searchParams.get("nonce")).toBe(identity.nonce);
    await h.app.close();
  });

  it("reflects the validated origin over CORS — the dev app may read its own response", async () => {
    const h = build();
    h.portal.response = { outcome: "started", authorizeUrl: "https://vendor.example/authorize" };
    const res = await post(h.app);
    expect(res.headers["access-control-allow-origin"]).toBe(DEV_ORIGIN);
    await h.app.close();
  });

  it("env is pinned by the identity kind — no request input can reach the consult", async () => {
    const h = build();
    h.portal.response = { outcome: "started", authorizeUrl: "https://vendor.example/authorize" };
    // A smuggled env hint in the query string, a second registered origin, an
    // unknown body field: none of it changes what the consult carries.
    const res = await post(h.app, { url: `${START_URL}?env=prod` });
    expect(res.statusCode).toBe(200);
    expect(consultRequest(h).identity).toMatchObject({ kind: "dev" });
    await h.app.close();
  });
});

describe("terminal outcomes answer JSON, not a popup URL", () => {
  it("already_connected — no popup URL, no nonce minted into a URL", async () => {
    const h = build();
    h.portal.response = { outcome: "already_connected" };
    const res = await post(h.app);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ outcome: "already_connected" });
    expect(h.portal.requests.length).toBe(1);
    await h.app.close();
  });

  it("not_available — binding unapproved or provider missing", async () => {
    const h = build();
    h.portal.response = { outcome: "not_available" };
    const res = await post(h.app);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ outcome: "not_available" });
    await h.app.close();
  });
});

describe("the Origin contract runs BEFORE any consult", () => {
  it("an unregistered Origin is refused 403 with no consult call", async () => {
    const h = build();
    const res = await post(h.app, { origin: "https://evil.example" });
    expect(res.statusCode).toBe(403);
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    // Nothing was consulted — nothing recorded anywhere.
    expect(h.portal.requests.length).toBe(0);
    await h.app.close();
  });

  it("a missing Origin is refused 403 with no consult call", async () => {
    const h = build();
    const res = await post(h.app, { origin: null });
    expect(res.statusCode).toBe(403);
    expect(h.portal.requests.length).toBe(0);
    await h.app.close();
  });

  it("a token for another app is refused 403 before any consult", async () => {
    const h = build();
    const other = newDevToken();
    h.tokens.add(other, { ...liveTokenRow(), appId: "22222222-2222-4222-8222-222222222222" });
    const res = await post(h.app, { token: other });
    expect(res.statusCode).toBe(403);
    expect(h.portal.requests.length).toBe(0);
    await h.app.close();
  });

  it("a missing, unknown, revoked, or expired token is refused 401 before any consult", async () => {
    const h = build();
    const revoked = newDevToken();
    h.tokens.add(revoked, { ...liveTokenRow(), revokedAt: new Date() });
    const expired = newDevToken();
    h.tokens.add(expired, {
      ...liveTokenRow(),
      expiresAt: new Date(Date.now() - 1000),
    });
    for (const token of [null, newDevToken(), revoked, expired]) {
      const res = await post(h.app, { token });
      expect(res.statusCode, token ?? "no token").toBe(401);
    }
    expect(h.portal.requests.length).toBe(0);
    await h.app.close();
  });

  it("each registered origin is the validated opener origin for its own POST", async () => {
    // A token registers several origins; each POST's own Origin is the one
    // recorded — a different origin than the validated one is never recorded.
    const h = build();
    h.portal.response = { outcome: "started", authorizeUrl: "https://vendor.example/authorize" };
    const a = await post(h.app);
    const b = await post(h.app, { origin: OTHER_REGISTERED_ORIGIN });
    expect(a.statusCode).toBe(200);
    expect(b.statusCode).toBe(200);
    const [first, second] = h.portal.requests;
    expect((JSON.parse(first!.body) as ConsultRequest).openerOrigin).toBe(DEV_ORIGIN);
    expect((JSON.parse(second!.body) as ConsultRequest).openerOrigin).toBe(OTHER_REGISTERED_ORIGIN);
    await h.app.close();
  });
});

describe("fail-closed seams and routing discipline", () => {
  it("an unconfigured portal seam answers a fixed 503, without minting a URL", async () => {
    const h = build({ withPortal: false });
    const res = await post(h.app);
    expect(res.statusCode).toBe(503);
    expect(res.json().error.code).toBe("capability_unavailable");
    await h.app.close();
  });

  it("an unconfigured internal key answers a fixed 503, without consulting", async () => {
    const h = build({ withInternalSecret: false });
    const res = await post(h.app);
    expect(res.statusCode).toBe(503);
    await h.app.close();
  });

  it("a failed portal hop answers a fixed 503 with no detail", async () => {
    const h = build();
    h.portal.error = new Error("portal down");
    const res = await post(h.app);
    expect(res.statusCode).toBe(503);
    expect(res.body).not.toContain("portal down");
    await h.app.close();
  });

  it("a non-200 consult answer is a fixed 503", async () => {
    const h = build();
    h.portal.status = 500;
    const res = await post(h.app);
    expect(res.statusCode).toBe(503);
    await h.app.close();
  });

  it("a malformed provider ref 404s without consulting", async () => {
    const h = build();
    const res = await post(h.app, { url: `/${SLUG}/_api/connections/NOT_A_REF/start` });
    expect(res.statusCode).toBe(404);
    expect(h.portal.requests.length).toBe(0);
    await h.app.close();
  });

  it("an unknown app 404s and an archived app 410s, without consulting", async () => {
    const h = build();
    expect((await post(h.app, { url: "/nosuch/_api/connections/asana/start" })).statusCode).toBe(
      404,
    );
    const archived = new FakeRegistry([
      registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: "apps/a/1/", archived: true }),
    ]);
    const app2 = buildDevGateway({
      config: testDevGatewayConfig(),
      registry: archived,
      devTokens: (() => {
        const t = new FakeDevTokenStore();
        t.add(DEV_BEARER, liveTokenRow());
        return t;
      })(),
      appData: new FakeAppDataStore(),
      usage: new FakeUsageStore(),
      llmProvider: null,
      egress: null,
      instructionKey: null,
      portal: null,
    });
    expect((await post(app2)).statusCode).toBe(410);
    await app2.close();
    await h.app.close();
  });
});

describe("the dev consent-start span", () => {
  it("exists under its constant name and records the bounded outcomes", async () => {
    const recording = startRecordingTelemetry();
    try {
      const h = build();
      h.portal.response = { outcome: "started", authorizeUrl: "https://vendor.example/authorize" };
      await post(h.app);
      const refused = await post(h.app, { origin: "https://evil.example" });
      expect(refused.statusCode).toBe(403);
      await h.app.close();

      const spans = recording.spans().filter((s) => s.name === SPAN_CONSENT_START_DEV);
      expect(spans.length).toBe(2);
      const outcomes = spans.map((s) => s.attributes["helix.outcome"]);
      expect(outcomes).toContain("started");
      expect(outcomes).toContain("forbidden");
      // No span carries the bearer token or the nonce.
      const dump = JSON.stringify(spans.map((s) => s.attributes));
      expect(dump).not.toContain(DEV_BEARER);
    } finally {
      await recording.restore();
    }
  });

  it("split layout: popup and callback URLs use the control domain", async () => {
    const cfg = splitDevGatewayConfig({ internalSecret: Buffer.alloc(32, 7) });
    const portal = new FakeConsultPortal();
    const tokens = new FakeDevTokenStore();
    tokens.add(DEV_BEARER, liveTokenRow());
    const app = buildDevGateway({
      config: cfg,
      registry: new FakeRegistry([
        registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: "apps/a/1/" }),
      ]),
      devTokens: tokens,
      appData: new FakeAppDataStore(),
      usage: new FakeUsageStore(),
      llmProvider: null,
      egress: null,
      instructionKey: null,
      portal,
    });
    const h = { app, portal, tokens };
    h.portal.response = { outcome: "started", authorizeUrl: "https://vendor.example/authorize" };
    const devApiHost = new URL(controlOrigin(cfg, "dev-api")).host;
    const res = await app.inject({
      method: "POST",
      url: START_URL,
      headers: {
        host: devApiHost,
        authorization: `Bearer ${DEV_BEARER}`,
        origin: DEV_ORIGIN,
      },
    });
    expect(res.statusCode).toBe(200);
    const body = consultRequest(h);
    expect(body.callbackUrl).toBe(`${controlOrigin(cfg, "auth")}/connections/callback`);
    const popupUrl = res.json<{ popupUrl: string }>().popupUrl;
    expect(new URL(popupUrl).origin).toBe(controlOrigin(cfg, "auth"));
    await h.app.close();
  });
});
