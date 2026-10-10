import { randomUUID } from "node:crypto";
import { Readable } from "node:stream";
import { jwtVerify } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import {
  CONNECT_MESSAGE_VERSION,
  ConsultRequestSchema,
  type ConsultResponse,
  HELIX_CONNECT_MESSAGE_SOURCE,
  INTERNAL_AUTH_HEADER,
  INTERNAL_AUDIENCE,
  INTERNAL_JWT_TYP,
  INTERNAL_TTL_SECONDS,
} from "@azx-pbc/shared";
import { SPAN_CONSENT_START } from "@azx-pbc/shared/telemetry";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import { buildApp } from "../app.js";
import { deriveInternalKey } from "../internalJwt.js";
import { SESSION_COOKIE } from "../auth/cookies.js";
import { hashSessionToken, newSessionToken } from "../auth/sessions.js";
import { controlOrigin, publicOrigin } from "../config.js";
import { splitEdgeConfig, testAuthConfig, testEdgeConfig } from "../test/config.js";
import {
  FakeBlobReader,
  FakeOidcClient,
  FakeRegistry,
  FakeSessionStore,
  registryEntry,
} from "../test/fakes.js";
import type { PortalProvider, PortalProxyRequest, PortalProxyResponse } from "./portalProvider.js";
import { randomBytes } from "node:crypto";

/**
 * `GET /_api/connections/:ref/start` — the consent popup's prod
 * entry. The consult rides a scripted fake portal provider (the
 * `fetch.test.ts` FakeEgress seam style: capture what the edge forwards,
 * answer a scripted contract), so every assertion here is against the real
 * route, guard, session check, and page rendering — only the portal hop is
 * fake.
 */

const APP_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const SLUG = "demo";
const HOST = { host: "demo.local.helix.azxlabs.io" };
const ORIGIN = "https://demo.local.helix.azxlabs.io:8080";
const EVIL_ORIGIN = "https://evil.example";
const SIBLING_ORIGIN = "https://sibling.local.helix.azxlabs.io:8080";
const AUTH_HOST = { host: "auth.local.helix.azxlabs.io" };
const PLATFORM_HOST = { host: "localhost:8080" };
const START_URL = "/_api/connections/asana/start";
const CALLBACK_URL = "https://auth.local.helix.azxlabs.io:8080/connections/callback";
const INTERNAL_SECRET = randomBytes(32);

/** Headers exactly as a real browser sends them for a same-origin popup
 * navigation: Fetch Metadata present, no Origin on a GET, Referer attached. */
const POPUP_HEADERS = {
  "sec-fetch-site": "same-origin",
  "sec-fetch-mode": "navigate",
  "sec-fetch-dest": "document",
  referer: `${ORIGIN}/page`,
};

/** A vendor authorize URL the fake consult "assembled" — state + S256 challenge. */
const CONSULT_STATE = "a".repeat(43);
const CONSULT_CHALLENGE = "X".repeat(43);
const authorizeUrl = (): string => {
  const u = new URL("https://vendor.example/oauth/authorize");
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", "client-123");
  u.searchParams.set("state", CONSULT_STATE);
  u.searchParams.set("code_challenge", CONSULT_CHALLENGE);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("redirect_uri", CALLBACK_URL);
  return u.toString();
};

/**
 * The fake portal provider for the consult seam: captures every request
 * (target, headers, body) and answers a scripted consult response — the
 * `fetch.test.ts` fake-seam shape. Its `requests` array is the call log the
 * ticket's done-conditions read ("no consult call, no flow row").
 */
class FakeConsultPortal implements PortalProvider {
  readonly requests: {
    target: string;
    headers: Record<string, unknown>;
    body: string;
    /** The edge-minted internal JWT (rides beside the safelisted headers). */
    internalToken: string;
  }[] = [];
  /** The consult response the next call gets (JSON body). */
  response: ConsultResponse = { outcome: "not_available" };
  /** Raw body override — malformed/invalid responses for the failure paths. */
  body: string | null = null;
  /** Status the next consult call answers with (non-200 = service failure). */
  status = 200;
  /** When set, the consult call rejects (portal hop failed). */
  error: Error | null = null;

  async proxy(req: PortalProxyRequest): Promise<PortalProxyResponse> {
    const chunks: Buffer[] = [];
    if (req.body) {
      for await (const chunk of req.body) chunks.push(chunk as Buffer);
    }
    this.requests.push({
      target: req.target,
      headers: req.headers,
      body: Buffer.concat(chunks).toString("utf8"),
      internalToken: req.internalToken,
    });
    if (this.error) throw this.error;
    return {
      status: this.status,
      headers: { "content-type": "application/json" },
      body: Readable.from([Buffer.from(this.body ?? JSON.stringify(this.response))]),
    };
  }

  async close(): Promise<void> {}
}

interface Harness {
  app: FastifyInstance;
  portal: FakeConsultPortal;
  sessions: FakeSessionStore;
  /** Sign in a fixture user and return the session cookie value. */
  signIn(opts?: {
    kind?: "user" | "password";
    groups?: string[];
    expired?: boolean;
  }): Promise<string>;
}

function buildConsentEdge(
  opts: {
    visibilityMode?: "internal" | "group";
    visibilityGroupIds?: string[];
    withPortal?: boolean;
    withInternalSecret?: boolean;
    config?: ReturnType<typeof testEdgeConfig>;
  } = {},
): Harness {
  const portal = new FakeConsultPortal();
  const sessions = new FakeSessionStore();
  const entry = registryEntry({
    appId: APP_ID,
    slug: SLUG,
    blobPrefix: "apps/b/1/",
    visibilityMode: opts.visibilityMode ?? "internal",
    visibilityGroupIds: opts.visibilityGroupIds ?? [],
  });
  const edgeConfig =
    opts.config ??
    testEdgeConfig({
      auth: testAuthConfig(),
      internalSecret: opts.withInternalSecret === false ? null : INTERNAL_SECRET,
    });
  const app = buildApp({
    config: edgeConfig,
    registry: new FakeRegistry([entry]),
    blob: new FakeBlobReader(),
    sessions,
    oidc: new FakeOidcClient(),
    portal: opts.withPortal === false ? null : portal,
  });
  return {
    app,
    portal,
    sessions,
    async signIn(overrides = {}) {
      const kind = overrides.kind ?? "user";
      const token = newSessionToken();
      const id = randomUUID();
      const now = Date.now();
      await sessions.createPending({
        id,
        appId: APP_ID,
        user: {
          oid: kind === "user" ? "oid-alice" : "pw_pseudonym1234",
          displayName: "Alice Anders",
          name: "Alice",
          email: "alice@azx.dev",
          kind,
          groups: overrides.groups ?? [],
        },
        refreshDueAt: new Date(now + 60_000),
        expiresAt: new Date(overrides.expired ? now - 1000 : now + 3_600_000),
      });
      await sessions.redeem(id, APP_ID, hashSessionToken(token));
      return token;
    },
  };
}

async function verifiesUnderPortalRule(token: unknown, key: Buffer): Promise<boolean> {
  if (typeof token !== "string") return false;
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

const INTERNAL_KEY = deriveInternalKey(INTERNAL_SECRET);

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

describe("the consent start route — started outcome", () => {
  it("302s a signed-in user straight to the vendor authorize URL", async () => {
    const h = buildConsentEdge();
    h.portal.response = { outcome: "started", authorizeUrl: authorizeUrl() };
    const token = await h.signIn();
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe(authorizeUrl());
    // The auth-callback precedent for consent URLs.
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
    await h.app.close();
  });

  it("the redirect carries the consult's state and S256 PKCE challenge", async () => {
    const h = buildConsentEdge();
    h.portal.response = { outcome: "started", authorizeUrl: authorizeUrl() };
    const token = await h.signIn();
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    const location = new URL(res.headers.location as string);
    expect(location.searchParams.get("state")).toBe(CONSULT_STATE);
    expect(location.searchParams.get("code_challenge")).toBe(CONSULT_CHALLENGE);
    expect(location.searchParams.get("code_challenge_method")).toBe("S256");
    await h.app.close();
  });

  it("the consult carries the verified identity, app, ref, opener origin, and the auth-host callback URL", async () => {
    const h = buildConsentEdge();
    h.portal.response = { outcome: "started", authorizeUrl: authorizeUrl() };
    const token = await h.signIn();
    await h.app.inject({
      method: "GET",
      url: `${START_URL}?attempt=corr-tag-1`,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(h.portal.requests).toHaveLength(1);
    const seen = h.portal.requests[0]!;
    expect(seen.target).toBe("/internal/connections/consult");
    const body = ConsultRequestSchema.parse(JSON.parse(seen.body));
    expect(body.identity).toEqual({ kind: "user", userOid: "oid-alice" });
    expect(body.appSlug).toBe(SLUG);
    expect(body.providerRef).toBe("asana");
    // The guarded app origin — the value the completion message targets.
    expect(body.openerOrigin).toBe(ORIGIN);
    // From the edge's own auth-host origin.
    expect(body.callbackUrl).toBe(CALLBACK_URL);
    // The per-call internal JWT verifies under the portal's rule — and it
    // rides beside the safelisted headers, never inside them.
    expect(seen.headers[INTERNAL_AUTH_HEADER]).toBeUndefined();
    expect(await verifiesUnderPortalRule(seen.internalToken, INTERNAL_KEY)).toBe(true);
    await h.app.close();
  });

  it("carries no OAuth client code — the vendor side is only a consult response or a 302", async () => {
    // The edge never touches vendor endpoints itself: the only outbound call
    // in the happy path is the consult to the portal.
    const h = buildConsentEdge();
    h.portal.response = { outcome: "started", authorizeUrl: authorizeUrl() };
    const token = await h.signIn();
    await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(h.portal.requests).toHaveLength(1);
    expect(h.portal.requests[0]!.target).toBe("/internal/connections/consult");
    await h.app.close();
  });
});

describe("the same-origin navigation guard fails closed (adversarial matrix)", () => {
  async function refusedWith(
    headers: Record<string, string | string[]>,
    opts: { signedIn?: boolean } = {},
  ): Promise<{ status: number; consults: number }> {
    const h = buildConsentEdge();
    h.portal.response = { outcome: "started", authorizeUrl: authorizeUrl() };
    const headersOut: Record<string, string | string[]> = { ...HOST, ...headers };
    if (opts.signedIn !== false) {
      headersOut.cookie = `${SESSION_COOKIE}=${await h.signIn()}`;
    }
    const res = await h.app.inject({ method: "GET", url: START_URL, headers: headersOut });
    await h.app.close();
    return { status: res.statusCode, consults: h.portal.requests.length };
  }

  it.each([
    ["no headers at all (curl, no initiator)", {}],
    ["Sec-Fetch-Site: cross-site", { "sec-fetch-site": "cross-site" }],
    ["Sec-Fetch-Site: same-site (a sibling subdomain)", { "sec-fetch-site": "same-site" }],
    ["Sec-Fetch-Site: none (no initiator is a phishing channel)", { "sec-fetch-site": "none" }],
    [
      "cross-site Sec-Fetch-Site against a matching Origin — the negative wins",
      { "sec-fetch-site": "cross-site", origin: ORIGIN },
    ],
    [
      "same-site Sec-Fetch-Site against a matching Origin",
      { "sec-fetch-site": "same-site", origin: ORIGIN },
    ],
    [
      "SPOOFED Sec-Fetch-Site: same-origin with no Origin and no Referer",
      { "sec-fetch-site": "same-origin" },
    ],
    [
      "SPOOFED same-origin against a hostile Origin",
      { "sec-fetch-site": "same-origin", origin: EVIL_ORIGIN },
    ],
    [
      "SPOOFED same-origin against a hostile Referer",
      { "sec-fetch-site": "same-origin", referer: `${EVIL_ORIGIN}/page` },
    ],
    [
      "SPOOFED same-origin against hostile Origin + hostile Referer",
      {
        "sec-fetch-site": "same-origin",
        origin: EVIL_ORIGIN,
        referer: `${EVIL_ORIGIN}/page`,
      },
    ],
    [
      "same-origin claim, hostile Origin, matching Referer — the mismatch fails closed",
      { "sec-fetch-site": "same-origin", origin: EVIL_ORIGIN, referer: `${ORIGIN}/page` },
    ],
    ["hostile Origin alone", { origin: EVIL_ORIGIN }],
    ["hostile Referer alone", { referer: `${EVIL_ORIGIN}/page` }],
    ["hostile Origin + hostile Referer", { origin: EVIL_ORIGIN, referer: `${EVIL_ORIGIN}/page` }],
    ["sibling-subdomain Origin — same-site is not same-origin", { origin: SIBLING_ORIGIN }],
    [
      "repeated Origin header (array) — fail closed",
      { origin: [ORIGIN, ORIGIN] as unknown as string },
    ],
    ["unparseable Referer", { referer: "not-a-url" }],
    ["Origin with a path — an origin header is origin-only", { origin: `${ORIGIN}/page` }],
    ["empty Sec-Fetch-Site and no Origin/Referer", { "sec-fetch-site": "" }],
  ])("refuses: %s", async (_name, headers) => {
    const { status, consults } = await refusedWith(headers);
    expect(status).toBe(403);
    // The guard is the boundary: no consult, no flow row.
    expect(consults).toBe(0);
  });

  it("refuses a cross-site navigation even without a session (no identity signal either)", async () => {
    const { status, consults } = await refusedWith(
      { "sec-fetch-site": "cross-site" },
      { signedIn: false },
    );
    expect(status).toBe(403);
    expect(consults).toBe(0);
  });

  it.each([
    [
      "the real popup shape: same-origin Fetch Metadata + Referer (no Origin on a GET)",
      { "sec-fetch-site": "same-origin", referer: `${ORIGIN}/page` },
    ],
    [
      "same-origin Fetch Metadata + matching Origin",
      { "sec-fetch-site": "same-origin", origin: ORIGIN },
    ],
    ["older browser: no Fetch Metadata, matching Origin", { origin: ORIGIN }],
    ["older browser: no Fetch Metadata, matching Referer", { referer: `${ORIGIN}/page` }],
  ])("admits: %s", async (_name, headers) => {
    const { status, consults } = await refusedWith(headers);
    expect(status).toBe(302);
    expect(consults).toBe(1);
  });
});

describe("session is checked before the consult", () => {
  it("no session renders sign-in required — no consult call, no flow row", async () => {
    const h = buildConsentEdge();
    h.portal.response = { outcome: "started", authorizeUrl: authorizeUrl() };
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(401);
    // The fake provider's call log is the observable: no consult, no flow row.
    expect(h.portal.requests).toHaveLength(0);
    // The designed page content — consent never resumes through login.
    expect(res.body).toContain("Sign-in required");
    expect(res.body).toContain("Close this window, sign in to the app, then select Connect again.");
    // NOT a redirect into the OIDC flow.
    expect(res.headers.location).toBeUndefined();
    await h.app.close();
  });

  it("an expired session is sign-in required, without consulting", async () => {
    const h = buildConsentEdge();
    const token = await h.signIn({ expired: true });
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(401);
    expect(res.body).toContain("Sign-in required");
    expect(h.portal.requests).toHaveLength(0);
    await h.app.close();
  });

  it("a shared-password pseudonym is not an identified user", async () => {
    const h = buildConsentEdge();
    const token = await h.signIn({ kind: "password" });
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(401);
    expect(res.body).toContain("Sign-in required");
    expect(h.portal.requests).toHaveLength(0);
    await h.app.close();
  });

  it("a session that fails the app's visibility check is sign-in required", async () => {
    const h = buildConsentEdge({ visibilityMode: "group", visibilityGroupIds: ["eng-team"] });
    const token = await h.signIn({ groups: ["other-team"] });
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(401);
    expect(h.portal.requests).toHaveLength(0);
    await h.app.close();
  });

  it("the sign-in-required page posts its outcome message to the app's own origin", async () => {
    const h = buildConsentEdge();
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, ...POPUP_HEADERS },
    });
    expect(res.body).toContain('"outcome":"signin_required"');
    expect(res.body).toContain(`"source":"${HELIX_CONNECT_MESSAGE_SOURCE}"`);
    expect(res.body).toContain(`"version":${CONNECT_MESSAGE_VERSION}`);
    expect(res.body).toContain(ORIGIN);
    await h.app.close();
  });
});

describe("terminal outcomes render the design's pages", () => {
  it("already connected — content, message, and no attempt row", async () => {
    const h = buildConsentEdge();
    h.portal.response = { outcome: "already_connected" };
    const token = await h.signIn();
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("already connected to asana.");
    expect(res.body).toContain('"outcome":"already_connected"');
    expect(res.body).toContain('"reason":null');
    await h.app.close();
  });

  it("the terminal page echoes a supplied attempt tag into the message", async () => {
    const h = buildConsentEdge();
    h.portal.response = { outcome: "already_connected" };
    const token = await h.signIn();
    const res = await h.app.inject({
      method: "GET",
      url: `${START_URL}?attempt=corr-tag-1`,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.body).toContain('"attempt":"corr-tag-1"');
    await h.app.close();
  });

  it("no attempt tag in, no attempt field in the message", async () => {
    const h = buildConsentEdge();
    h.portal.response = { outcome: "already_connected" };
    const token = await h.signIn();
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.body).not.toContain('"attempt"');
    await h.app.close();
  });

  it("not available — provider missing or binding unapproved", async () => {
    const h = buildConsentEdge();
    h.portal.response = { outcome: "not_available" };
    const token = await h.signIn();
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("This connection isn&#39;t available for this app right now.");
    expect(res.body).toContain('"outcome":"error"');
    expect(res.body).toContain('"reason":"provider_unavailable"');
    await h.app.close();
  });

  it("a failed consult hop renders couldn't-start", async () => {
    const h = buildConsentEdge();
    h.portal.error = new Error("portal hop failed");
    const token = await h.signIn();
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain("start the connection — close this and select Connect again");
    expect(res.body).toContain('"outcome":"error"');
    expect(res.body).toContain('"reason":"service_unavailable"');
    await h.app.close();
  });

  it("a non-200 consult answer renders couldn't-start", async () => {
    const h = buildConsentEdge();
    h.portal.status = 503;
    h.portal.body = "portal unavailable";
    const token = await h.signIn();
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain("start the connection — close this and select Connect again");
    await h.app.close();
  });

  it("a malformed or schema-invalid consult body renders couldn't-start", async () => {
    for (const bad of ["not json", JSON.stringify({ outcome: "started" })]) {
      const h = buildConsentEdge();
      h.portal.body = bad;
      const token = await h.signIn();
      const res = await h.app.inject({
        method: "GET",
        url: START_URL,
        headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
      });
      expect(res.statusCode).toBe(503);
      expect(res.body).toContain("start the connection — close this and select Connect again");
      await h.app.close();
    }
  });

  it("an authorize URL that is not https renders couldn't-start (redirect hygiene)", async () => {
    const h = buildConsentEdge();
    h.portal.response = {
      outcome: "started",
      authorizeUrl: "http://vendor.example/oauth/authorize?state=x",
    };
    const token = await h.signIn();
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(503);
    expect(h.portal.requests).toHaveLength(1); // the consult ran; the redirect didn't
    await h.app.close();
  });

  it("an unconfigured portal seam renders couldn't-start, fail-closed", async () => {
    const h = buildConsentEdge({ withPortal: false });
    const token = await h.signIn();
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain("start the connection — close this and select Connect again");
    await h.app.close();
  });

  it("an unconfigured internal key renders couldn't-start, fail-closed", async () => {
    const h = buildConsentEdge({ withInternalSecret: false });
    const token = await h.signIn();
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain("start the connection — close this and select Connect again");
    expect(h.portal.requests).toHaveLength(0);
    await h.app.close();
  });
});

describe("the popup pages' contract", () => {
  async function pageOf(outcome: ConsultResponse): Promise<{
    status: number;
    body: string;
    headers: Record<string, unknown>;
  }> {
    const h = buildConsentEdge();
    h.portal.response = outcome;
    const token = await h.signIn();
    const res = await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    await h.app.close();
    return { status: res.statusCode, body: res.body, headers: res.headers };
  }

  it("every terminal page is no-store, focuses its heading on load, and has a real Close button", async () => {
    for (const outcome of [
      { outcome: "already_connected" },
      { outcome: "not_available" },
    ] as const) {
      const page = await pageOf(outcome);
      expect(page.headers["cache-control"]).toBe("no-store");
      // Heading focus on load: the h1 is script-focusable and the page's own
      // inline script focuses it.
      expect(page.body).toContain('<h1 tabindex="-1">');
      expect(page.body).toContain("heading.focus()");
      // A real button — keyboard-reachable by construction.
      expect(page.body).toContain('<button type="button"');
      expect(page.body).toContain(">Close</button>");
      expect(page.body).toContain("window.close()");
    }
  });

  it("every terminal page posts the message to the app's own origin before closing", async () => {
    const page = await pageOf({ outcome: "already_connected" });
    expect(page.body).toContain("postMessage(message, targetOrigin)");
    // The embedded target origin is the guarded app origin —
    // "the app's own host for start-route pages".
    expect(page.body).toContain(ORIGIN);
  });

  it("the pages' CSP allows the one inline script and nothing else", async () => {
    const page = await pageOf({ outcome: "not_available" });
    const csp = page.headers["content-security-policy"] as string;
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'unsafe-inline'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it("script interpolation survives a hostile-looking message value", async () => {
    // Provider refs are pattern-validated, so this cannot occur end to end —
    // assert the serializer anyway, since the script's safety rests on it.
    const { scriptJson } = await import("../serving/consentPages.js");
    expect(scriptJson({ x: "</script><script>alert(1)</script>" })).not.toContain("</script>");
    expect(scriptJson("a\u2028b")).not.toContain("\u2028");
  });
});

describe("route discipline", () => {
  it("is an app-host route: the auth host and platform hosts 404 it", async () => {
    const h = buildConsentEdge();
    for (const headers of [AUTH_HOST, PLATFORM_HOST]) {
      const res = await h.app.inject({ method: "GET", url: START_URL, headers });
      expect(res.statusCode).toBe(404);
    }
    expect(h.portal.requests).toHaveLength(0);
    await h.app.close();
  });

  it("an unknown app 404s without consulting", async () => {
    const h = buildConsentEdge();
    const token = await h.signIn();
    // The guard runs before app resolution, so this navigation must look
    // same-origin to the host it names.
    const nosuchOrigin = "https://nosuch.local.helix.azxlabs.io:8080";
    const res = await h.app.inject({
      method: "GET",
      url: "/_api/connections/asana/start",
      headers: {
        host: "nosuch.local.helix.azxlabs.io",
        cookie: `${SESSION_COOKIE}=${token}`,
        "sec-fetch-site": "same-origin",
        referer: `${nosuchOrigin}/page`,
      },
    });
    expect(res.statusCode).toBe(404);
    expect(h.portal.requests).toHaveLength(0);
    await h.app.close();
  });

  it("a malformed provider ref 404s without consulting", async () => {
    const h = buildConsentEdge();
    const token = await h.signIn();
    for (const ref of ["ASANA", "not a ref", "../etc"]) {
      const res = await h.app.inject({
        method: "GET",
        url: `/_api/connections/${encodeURIComponent(ref)}/start`,
        headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
      });
      expect(res.statusCode).toBe(404);
    }
    expect(h.portal.requests).toHaveLength(0);
    await h.app.close();
  });

  it("an invalid or repeated attempt tag is a 400, without consulting", async () => {
    const h = buildConsentEdge();
    const token = await h.signIn();
    for (const query of [
      "?attempt=not%20safe",
      "?attempt=",
      "?attempt=a&attempt=b",
      "?attempt=" + "x".repeat(129),
    ]) {
      const res = await h.app.inject({
        method: "GET",
        url: `${START_URL}${query}`,
        headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
      });
      expect(res.statusCode).toBe(400);
    }
    expect(h.portal.requests).toHaveLength(0);
    await h.app.close();
  });

  it("an archived app 410s (the serving posture, unchanged)", async () => {
    const sessions = new FakeSessionStore();
    const portal = new FakeConsultPortal();
    const app = buildApp({
      config: testEdgeConfig({ auth: testAuthConfig(), internalSecret: INTERNAL_SECRET }),
      registry: new FakeRegistry([
        registryEntry({ appId: APP_ID, slug: SLUG, blobPrefix: "apps/b/1/", archived: true }),
      ]),
      blob: new FakeBlobReader(),
      sessions,
      oidc: new FakeOidcClient(),
      portal,
    });
    const res = await app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, ...POPUP_HEADERS },
    });
    expect(res.statusCode).toBe(410);
    expect(portal.requests).toHaveLength(0);
    await app.close();
  });
});

describe("the consent-start span", () => {
  it("carries the outcome vocabulary on every decided path", async () => {
    const h = buildConsentEdge();
    h.portal.response = { outcome: "started", authorizeUrl: authorizeUrl() };
    const token = await h.signIn();
    await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, cookie: `${SESSION_COOKIE}=${token}`, ...POPUP_HEADERS },
    });
    await h.app.close();

    const span = recording.spans().find((s) => s.name === SPAN_CONSENT_START);
    expect(span).toBeDefined();
    expect(span?.attributes["helix.outcome"]).toBe("started");
    expect(span?.attributes["http.route"]).toBe("/_api/connections/:ref/start");
    expect(span?.attributes["url.path"]).toBe("/_api/connections/asana/start");
    expect(span?.attributes["helix.provider_ref"]).toBe("asana");
  });

  it("records forbidden for a guard refusal and signin_required without a session", async () => {
    const h = buildConsentEdge();
    await h.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, "sec-fetch-site": "cross-site" },
    });
    const fresh = buildConsentEdge();
    await fresh.app.inject({
      method: "GET",
      url: START_URL,
      headers: { ...HOST, ...POPUP_HEADERS },
    });
    await fresh.app.close();

    const outcomes = recording
      .spans()
      .filter((s) => s.name === SPAN_CONSENT_START)
      .map((s) => s.attributes["helix.outcome"]);
    expect(outcomes).toContain("forbidden");
    expect(outcomes).toContain("signin_required");
  });

  it("split layout: consult uses control callback and apps opener origin", async () => {
    const cfg = splitEdgeConfig({ auth: testAuthConfig(), internalSecret: INTERNAL_SECRET });
    const h = buildConsentEdge({ config: cfg });
    h.portal.response = { outcome: "started", authorizeUrl: authorizeUrl() };
    const token = await h.signIn();
    const appOrigin = publicOrigin(cfg, SLUG);
    const res = await h.app.inject({
      method: "GET",
      url: `${START_URL}?attempt=corr-tag-1`,
      headers: {
        host: new URL(appOrigin).host,
        cookie: `${SESSION_COOKIE}=${token}`,
        ...POPUP_HEADERS,
        referer: `${appOrigin}/page`,
      },
    });
    expect(res.statusCode).toBe(302);
    expect(h.portal.requests).toHaveLength(1);
    const body = ConsultRequestSchema.parse(JSON.parse(h.portal.requests[0]!.body));
    expect(body.openerOrigin).toBe(appOrigin);
    expect(body.callbackUrl).toBe(`${controlOrigin(cfg, "auth")}/connections/callback`);
    await h.app.close();
  });
});
