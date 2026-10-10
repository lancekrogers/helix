import { randomBytes, randomUUID } from "node:crypto";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Writable } from "node:stream";
import { SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { request as undiciRequest } from "undici";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import {
  INSTRUCTION_AUDIENCE,
  INSTRUCTION_HEADER,
  INSTRUCTION_JWT_TYP,
  METHOD_HEADER,
  OUTCOME_HEADER,
  TARGET_HEADER,
} from "@azx-pbc/shared";
import {
  ATTR_CAPABILITY,
  INSTR_EGRESS_UPSTREAM_ABORTS,
  SPAN_EGRESS_PROXY,
} from "@azx-pbc/shared/telemetry";
import { buildApp } from "./app.js";
import type { EgressConfig } from "./config.js";
import { signTimestamp } from "./hmac.js";
import { deriveInstructionKey } from "./instruction.js";
import type { ResolvedConnection, SecretResolver } from "./secrets.js";

const secret = randomBytes(32);
const key = deriveInstructionKey(secret);

// Real in-memory span/metric providers, so the outcome-label assertions below
// pin what the *span* says — the thing alerting reads — not just the header.
let recording: RecordingTelemetry;

// An upstream that echoes what it received, so we can assert injection + method.
let upstream: Server;
let origin: string;
beforeAll(async () => {
  recording = startRecordingTelemetry();
  upstream = createServer((req, res) => {
    // A throttling route: egress must label the proxied 429 so alerting on
    // `helix.outcome` can distinguish a vendor throttle from a clean pass.
    if (req.url === "/throttle") {
      res.writeHead(429, { "content-type": "application/json", "retry-after": "30" });
      res.end(JSON.stringify({ error: { code: "429", message: "Rate limit exceeded" } }));
      return;
    }
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          method: req.method,
          path: req.url,
          authorization: req.headers["authorization"] ?? null,
          host: req.headers["host"] ?? null,
          cookie: req.headers["cookie"] ?? null,
          xDate: req.headers["x-date"] ?? null,
          // Echo the received body so tests can assert it transited intact.
          received: Buffer.concat(chunks).toString("utf8"),
        }),
      );
    });
  });
  await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});
afterEach(() => recording.reset());
afterAll(async () => {
  await recording.restore();
  await new Promise<void>((resolve) => upstream.close(() => resolve()));
});

/** The private half of the hmac fixture pair — also the needle for leak assertions. */
const HMAC_PRIVATE = "ghp_LIVEPRIVATEKEY_abcdefghijklmnop";
const HMAC_BLOB = JSON.stringify({ credential: "pub-abc", key: HMAC_PRIVATE });
const HMAC_RECIPE = {
  kind: "hmac-timestamp",
  timestampHeader: "x-date",
  authHeader: "authorization",
  template: "Credential={credential},Signature={signature}",
} as const;

const fakeResolver: SecretResolver = {
  resolve: async (_appId, connection): Promise<ResolvedConnection | null> => {
    switch (connection) {
      case "gh":
        return { value: "ghp_secret", injection: { kind: "header-bearer" } };
      case "hmac":
        return { value: HMAC_BLOB, injection: HMAC_RECIPE };
      // A recipe⇄material mismatch: the recipe wants a blob, the material is a
      // bare token. The portal now refuses this at write time, but rows predating
      // that check exist, so the read path must fail closed and opaquely.
      case "hmac-bad":
        return { value: HMAC_PRIVATE, injection: HMAC_RECIPE };
      default:
        return null;
    }
  },
  close: async () => {},
};

function makeApp(allowPrivate: boolean, resolver: SecretResolver | null = fakeResolver) {
  const config = {
    limits: { maxBodyBytes: 1024 * 1024, timeoutMs: 5000, llmTimeoutMs: 30_000 },
    allowPrivate,
    // Loopback echo upstreams are http; open the cleartext-injection seam so
    // these functional tests exercise injection without TLS (the prod guard and
    // its refusal path are covered in adversarial.test.ts — issue #11).
    allowInsecureConnection: true,
  } as EgressConfig;
  // No burn store here: these functional tests each mint a fresh (unique jti)
  // instruction, so replay protection is irrelevant; it's covered on its own in
  // adversarial.test.ts.
  return buildApp({ config, resolver, instructionKey: key, burnStore: null });
}

async function mint(claims: {
  origin: string;
  connection?: string;
  appId?: string;
  capability?: "fetch" | "llm";
}): Promise<string> {
  // Unique requestId per call so a shared burn store (where wired) wouldn't
  // reject the second mint as a replay.
  const requestId = randomUUID();
  const jwt = new SignJWT({
    appId: claims.appId ?? "app-1",
    userOid: "user-1",
    capability: claims.capability ?? "fetch",
    origin: claims.origin,
    requestId,
    ...(claims.connection ? { connection: claims.connection } : {}),
  })
    .setProtectedHeader({ alg: "HS256", typ: INSTRUCTION_JWT_TYP })
    .setJti(requestId)
    .setAudience(INSTRUCTION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("30s");
  return jwt.sign(key);
}

describe("egress /proxy", () => {
  it("proxies a keyless GET and streams the upstream body back", async () => {
    const app = makeApp(true);
    const token = await mint({ origin });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/echo`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers[OUTCOME_HEADER]).toBe("ok");
    const body = res.json();
    expect(body.method).toBe("GET");
    expect(body.path).toBe("/echo");
    expect(body.authorization).toBeNull(); // keyless: nothing injected
    await app.close();
  });

  it("labels a proxied upstream 429 as upstream_throttled and forwards retry-after", async () => {
    const app = makeApp(true);
    const token = await mint({ origin });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/throttle`,
        [METHOD_HEADER]: "GET",
      },
    });
    // The 429 is proxied verbatim — egress does not decide it's a failure — but
    // the outcome label distinguishes it from a clean pass, and the vendor's
    // retry-after (not blocklisted) survives to the caller.
    expect(res.statusCode).toBe(429);
    expect(res.headers[OUTCOME_HEADER]).toBe("upstream_throttled");
    expect(res.headers["retry-after"]).toBe("30");

    // The span agrees with the header — this is what alerting reads. Previously
    // a real vendor throttle presented as `outcome: "ok"` + the status buried in
    // `helix.upstream.status`, and anything keyed on outcome missed it entirely.
    // Span status stays UNSET: a 429 from the vendor is not egress failing.
    const spans = recording.spans();
    expect(spans).toHaveLength(1);
    expect(spans[0]?.attributes["helix.outcome"]).toBe("upstream_throttled");
    expect(spans[0]?.attributes["helix.upstream.status"]).toBe(429);
    expect(spans[0]?.status.code).toBe(0); // UNSET
    await app.close();
  });

  it("injects a connection secret server-side (app never sent it)", async () => {
    const app = makeApp(true);
    const token = await mint({ origin, connection: "gh" });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().authorization).toBe("Bearer ghp_secret");
    await app.close();
  });

  it("derives an hmac-timestamp credential the app never computed", async () => {
    const app = makeApp(true);
    const token = await mint({ origin, connection: "hmac" });
    const before = Date.now();
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.authorization).toMatch(/^Credential=pub-abc,Signature=[0-9a-f]{64}$/);
    // The timestamp went out as a real, current ISO instant.
    const sent = Date.parse(body.xDate);
    expect(sent).toBeGreaterThanOrEqual(before - 1000);
    expect(sent).toBeLessThanOrEqual(Date.now() + 1000);
    // Neither the private key nor the raw blob transited to the upstream.
    expect(res.payload).not.toContain(HMAC_PRIVATE);
    expect(res.payload).not.toContain('"key"');
    await app.close();
  });

  /**
   * The end-to-end binding test: recompute the signature over the timestamp the
   * upstream actually received. It fails if the two headers ever come from
   * different clock readings, or if the transmitted timestamp format diverges from
   * the signed one — a class of bug that authenticates locally and 401s in prod.
   */
  it("signs exactly the timestamp it transmits", async () => {
    const app = makeApp(true);
    const token = await mint({ origin, connection: "hmac" });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    const body = res.json();
    const signature = /Signature=([0-9a-f]{64})$/.exec(body.authorization)?.[1];
    expect(signature).toBe(signTimestamp(HMAC_PRIVATE, body.xDate));
    await app.close();
  });

  it("refuses material that does not fit its recipe, opaquely", async () => {
    const app = makeApp(true);
    const token = await mint({ origin, connection: "hmac-bad" });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    // Indistinguishable from a vault failure: an app must not learn *why*.
    expect(res.statusCode).toBe(502);
    expect(res.json()).toEqual({
      code: "upstream_error",
      message: "connection secret unavailable",
    });
    // V8 embeds a ~10-character prefix of its input in a JSON.parse message. That
    // input is the private key here, so pin its absence explicitly rather than
    // trusting the full-string check alone.
    expect(res.payload).not.toContain(HMAC_PRIVATE);
    expect(res.payload).not.toContain(HMAC_PRIVATE.slice(0, 10));
    await app.close();
  });

  it("forwards a JSON POST body intact (not consumed by a content-type parser)", async () => {
    // Regression: Fastify's built-in application/json parser must not drain
    // req.raw before the handler re-streams it (the LLM path is always JSON).
    const app = makeApp(true);
    const token = await mint({ origin });
    const payload = JSON.stringify({ model: "claude-opus-4-8", messages: [{ role: "user" }] });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/v1/messages`,
        [METHOD_HEADER]: "POST",
        "content-type": "application/json",
      },
      payload,
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.method).toBe("POST");
    expect(body.received).toBe(payload); // body transited byte-for-byte
    await app.close();
  });

  it("refuses a connection the app was not granted", async () => {
    const app = makeApp(true);
    const token = await mint({ origin, connection: "nope" });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe("forbidden");
    await app.close();
  });

  /**
   * Authority validation (bug-class ledger: secret-bearing requests to URLs
   * without authority validation). `URL.origin` ignores userinfo, so the origin
   * binding above cannot see `user:pass@` — and undici silently dials such a
   * URL rather than refusing it, normalizing credentials into an outbound call
   * they were never meant to carry. Credentials live in the connection store,
   * never the target; refuse instead of normalizing.
   */
  it("refuses a target carrying userinfo credentials", async () => {
    const app = makeApp(true);
    const token = await mint({ origin });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        // Same origin as the instruction — only the userinfo differs, which is
        // exactly the component the origin check cannot see.
        [TARGET_HEADER]: `${origin.replace("http://", "http://user:pass@")}/echo`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().code).toBe("bad_target");
    await app.close();
  });

  /**
   * Header injection (bug-class ledger): a connection secret is configured
   * material, but a value carrying CR/LF must never be able to smuggle extra
   * headers into the outbound request. undici refuses such header values, the
   * throw is contained to the opaque 502, and nothing reaches the upstream.
   */
  it("contains a connection secret carrying control characters", async () => {
    const app = makeApp(true, {
      resolve: async () => ({
        value: "leak\r\nX-Evil: injected",
        injection: { kind: "header-bearer" } as const,
      }),
      close: async () => {},
    });
    const token = await mint({ origin, connection: "gh" });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/echo`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(502);
    expect(res.headers[OUTCOME_HEADER]).toBe("error");
    // The echo upstream answers only if the poisoned request actually went out;
    // the opaque 502 means it never did.
    expect(res.payload).not.toContain("injected");
    await app.close();
  });

  it("rejects a forged/absent instruction", async () => {
    const app = makeApp(true);
    const missing = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: { [TARGET_HEADER]: `${origin}/` },
    });
    expect(missing.statusCode).toBe(400);

    const forged = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: { [INSTRUCTION_HEADER]: "not.a.jwt", [TARGET_HEADER]: `${origin}/` },
    });
    expect(forged.statusCode).toBe(401);
    await app.close();
  });

  it("rejects a target whose origin does not match the instruction", async () => {
    const app = makeApp(true);
    const token = await mint({ origin: "https://api.elsewhere.com" });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: { [INSTRUCTION_HEADER]: token, [TARGET_HEADER]: `${origin}/` },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe("forbidden");
    await app.close();
  });

  it("blocks a loopback target when private ranges are not allowed (SSRF)", async () => {
    const app = makeApp(false); // prod posture
    const token = await mint({ origin });
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: { [INSTRUCTION_HEADER]: token, [TARGET_HEADER]: `${origin}/` },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe("blocked");
    await app.close();
  });
});

describe("egress /proxy — connection pooling (ADR-0005 perf note)", () => {
  // The validate-and-pin moved into a shared dispatcher's connector, so repeated
  // calls to the same origin must reuse keep-alive sockets instead of paying a
  // fresh TCP+TLS handshake per call (the old per-request `Agent`). Guards against
  // a regression back to per-request dispatchers.
  it("reuses keep-alive sockets across requests to the same origin", async () => {
    let connections = 0;
    const server = createServer((_req, res) => res.end("ok"));
    server.on("connection", () => void connections++);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const localOrigin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    const app = makeApp(true);
    const requests = 6;
    for (let i = 0; i < requests; i++) {
      const res = await app.inject({
        method: "POST",
        url: "/proxy",
        headers: {
          [INSTRUCTION_HEADER]: await mint({ origin: localOrigin }),
          [TARGET_HEADER]: `${localOrigin}/`,
          [METHOD_HEADER]: "GET",
        },
      });
      expect(res.statusCode).toBe(200);
    }

    // Per-request Agents would open one TCP connection per request; a shared,
    // pooled dispatcher opens far fewer (typically one).
    expect(connections).toBeLessThan(requests);

    await app.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("egress /proxy — client hang-up after the first byte (characterization)", () => {
  // Result on main (792557a): passes — the vendor response closed ~10–15 ms after the hang-up
  // (10× run in the dev container, no flake). The claim under test is that a hang-up after
  // the upstream headers arrive already tears down the vendor connection, through Fastify's
  // sendStream -> capBody pipeline -> undici body destroy. It says nothing about a hang-up
  // BEFORE the headers arrive; that window is closed by the next change.
  let slow: Server;
  let slowOrigin: string;
  // Count HTTP requests, not TCP connections: after an aborted stream undici's pool can
  // open an idle connection that carries no request, and that is not a retry.
  let requests = 0;
  let closedEarly = false;

  beforeAll(async () => {
    slow = createServer((req, res) => {
      requests += 1;
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write("data: first\n\n");
      let sent = 1;
      const timer = setInterval(() => {
        res.write("data: more\n\n");
        // /finite ends by itself after a few chunks; /stream would run for 10 s.
        if (req.url === "/finite" && ++sent >= 4) {
          clearInterval(timer);
          res.end();
        }
      }, 25);
      const stop = setTimeout(() => {
        clearInterval(timer);
        res.end();
      }, 10_000);
      // 'close' fires when the socket goes away. writableFinished is still false when
      // the connection was torn down before end() ran.
      res.on("close", () => {
        clearInterval(timer);
        clearTimeout(stop);
        if (!res.writableFinished) closedEarly = true;
      });
    });
    await new Promise<void>((resolve) => slow.listen(0, "127.0.0.1", resolve));
    slowOrigin = `http://127.0.0.1:${(slow.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    slow.closeAllConnections();
    await new Promise<void>((resolve) => slow.close(() => resolve()));
  });

  async function callThroughSocket(path: string) {
    const app = makeApp(true);
    await app.listen({ port: 0, host: "127.0.0.1" });
    const base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
    requests = 0;
    closedEarly = false;
    const res = await undiciRequest(`${base}/proxy`, {
      method: "POST",
      headers: {
        [INSTRUCTION_HEADER]: await mint({ origin: slowOrigin }),
        [TARGET_HEADER]: `${slowOrigin}${path}`,
        [METHOD_HEADER]: "GET",
      },
    });
    return { app, res };
  }

  it("closes the vendor connection when the client hangs up after the first chunk", async () => {
    const { app, res } = await callThroughSocket("/stream");
    expect(res.statusCode).toBe(200);
    await res.body[Symbol.asyncIterator]().next(); // the first chunk has arrived
    res.body.destroy(); // the hang-up
    await vi.waitFor(() => expect(closedEarly).toBe(true), { timeout: 2_000, interval: 10 });
    // Egress did not send a second request to recover or retry.
    await new Promise((r) => setTimeout(r, 150));
    expect(requests).toBe(1);
    app.server.closeAllConnections();
    await app.close();
  });

  it("control: a client that stays connected sees the upstream finish normally", async () => {
    const { app, res } = await callThroughSocket("/finite");
    await res.body.text(); // read to the end
    await new Promise((r) => setTimeout(r, 100));
    expect(closedEarly).toBe(false);
    app.server.closeAllConnections();
    await app.close();
  });
});

async function metricTotal(name: string, match: Record<string, string>): Promise<number> {
  const points = await recording.metrics();
  return points
    .filter(
      (m) => m.name === name && Object.entries(match).every(([k, v]) => m.attributes[k] === v),
    )
    .reduce((sum, m) => sum + m.value, 0);
}

describe("egress /proxy — hang-up before the headers (upstream abort)", () => {
  let slowHeaders: Server;
  let slowHeadersOrigin: string;
  let upstreamSawClose = false;
  let headerDelayTimer: ReturnType<typeof setTimeout> | undefined;

  beforeAll(async () => {
    slowHeaders = createServer((req, res) => {
      if (req.url === "/slow-headers") {
        res.on("error", () => {});
        const onGone = () => {
          if (headerDelayTimer !== undefined) clearTimeout(headerDelayTimer);
          upstreamSawClose = true;
        };
        res.on("close", onGone);
        req.on("close", onGone);
        headerDelayTimer = setTimeout(() => {
          res.writeHead(200, { "content-type": "text/plain" });
          res.end("late");
        }, 3000);
        return;
      }
      res.end("ok");
    });
    await new Promise<void>((resolve) => slowHeaders.listen(0, "127.0.0.1", resolve));
    slowHeadersOrigin = `http://127.0.0.1:${(slowHeaders.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    slowHeaders.closeAllConnections();
    await new Promise<void>((resolve) => slowHeaders.close(() => resolve()));
  });

  async function callSlowHeaders(
    app: ReturnType<typeof makeApp>,
    capability: "fetch" | "llm" = "fetch",
  ) {
    await app.listen({ port: 0, host: "127.0.0.1" });
    const base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
    upstreamSawClose = false;
    headerDelayTimer = undefined;
    const ac = new AbortController();
    const token = await mint({ origin: slowHeadersOrigin, capability });
    const req = undiciRequest(`${base}/proxy`, {
      method: "POST",
      signal: ac.signal,
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${slowHeadersOrigin}/slow-headers`,
        [METHOD_HEADER]: "GET",
      },
    });
    await new Promise((r) => setTimeout(r, 100));
    ac.abort();
    try {
      await req;
    } catch {
      // hang-up
    }
    await vi.waitFor(
      () => {
        expect(
          recording
            .spans()
            .some(
              (s) =>
                s.name === SPAN_EGRESS_PROXY && s.attributes["helix.client_disconnected"] === true,
            ),
        ).toBe(true);
      },
      { timeout: 2000, interval: 25 },
    );
    return app;
  }

  it("closes the upstream connection well before the header delay elapses", async () => {
    const app = makeApp(true);
    await callSlowHeaders(app, "fetch");
    await vi.waitFor(() => expect(upstreamSawClose).toBe(true), { timeout: 1000, interval: 25 });
    const span = recording.spans().find((s) => s.name === SPAN_EGRESS_PROXY);
    expect(span?.attributes["helix.client_disconnected"]).toBe(true);
    app.server.closeAllConnections();
    await app.close();
  });

  it("never dials the vendor when the client aborts during secret resolution", async () => {
    const before = await metricTotal(INSTR_EGRESS_UPSTREAM_ABORTS, {
      [ATTR_CAPABILITY]: "fetch",
    });

    let releaseResolve!: () => void;
    const waitingResolver: SecretResolver = {
      resolve: async () => {
        await new Promise<void>((resolve) => {
          releaseResolve = resolve;
        });
        return { value: "ghp_secret", injection: { kind: "header-bearer" } };
      },
      close: async () => {},
    };

    const app = makeApp(true, waitingResolver);
    await app.listen({ port: 0, host: "127.0.0.1" });
    const base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
    const ac = new AbortController();
    const token = await mint({ origin, connection: "gh" });
    const pending = undiciRequest(`${base}/proxy`, {
      method: "POST",
      signal: ac.signal,
      headers: {
        [INSTRUCTION_HEADER]: token,
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    await new Promise((r) => setTimeout(r, 50));
    ac.abort();
    // Resolution was still parked when the client left; finishing it must take the hang-up path.
    releaseResolve();
    try {
      await pending;
    } catch {
      // hang-up
    }
    await vi.waitFor(
      async () => {
        const after = await metricTotal(INSTR_EGRESS_UPSTREAM_ABORTS, {
          [ATTR_CAPABILITY]: "fetch",
        });
        expect(after - before).toBe(1);
      },
      { timeout: 2000, interval: 25 },
    );

    app.server.closeAllConnections();
    await app.close();
  });

  it("logs no upstream request failed warning on a pre-header hang-up", async () => {
    const chunks: string[] = [];
    const capture = new Writable({
      write(chunk: unknown, _enc: BufferEncoding, cb: (e?: Error | null) => void) {
        chunks.push(String(chunk));
        cb();
      },
    });
    const config = {
      limits: { maxBodyBytes: 1024 * 1024, timeoutMs: 5000, llmTimeoutMs: 30_000 },
      allowPrivate: true,
      allowInsecureConnection: true,
    } as EgressConfig;
    const app = buildApp(
      { config, resolver: fakeResolver, instructionKey: key, burnStore: null },
      { level: "warn", stream: capture },
    );
    await callSlowHeaders(app, "fetch");
    expect(chunks.join("")).not.toContain("upstream request failed");
    app.server.closeAllConnections();
    await app.close();
  });

  it("increments helix.egress.upstream_aborts with helix.capability only (fetch)", async () => {
    const before = await metricTotal(INSTR_EGRESS_UPSTREAM_ABORTS, {
      [ATTR_CAPABILITY]: "fetch",
    });
    const app = makeApp(true);
    await callSlowHeaders(app, "fetch");
    await vi.waitFor(
      async () => {
        const after = await metricTotal(INSTR_EGRESS_UPSTREAM_ABORTS, {
          [ATTR_CAPABILITY]: "fetch",
        });
        expect(after - before).toBe(1);
      },
      { timeout: 2000, interval: 25 },
    );
    const points = await recording.metrics();
    const added = points.filter(
      (m) =>
        m.name === INSTR_EGRESS_UPSTREAM_ABORTS &&
        m.attributes[ATTR_CAPABILITY] === "fetch" &&
        m.value > 0,
    );
    for (const p of added) {
      expect(Object.keys(p.attributes).sort()).toEqual([ATTR_CAPABILITY]);
    }
    app.server.closeAllConnections();
    await app.close();
  });

  it("increments helix.egress.upstream_aborts for an llm instruction", async () => {
    const before = await metricTotal(INSTR_EGRESS_UPSTREAM_ABORTS, {
      [ATTR_CAPABILITY]: "llm",
    });
    const app = makeApp(true);
    await callSlowHeaders(app, "llm");
    await vi.waitFor(
      async () => {
        const after = await metricTotal(INSTR_EGRESS_UPSTREAM_ABORTS, {
          [ATTR_CAPABILITY]: "llm",
        });
        expect(after - before).toBe(1);
      },
      { timeout: 2000, interval: 25 },
    );
    app.server.closeAllConnections();
    await app.close();
  });

  it("still pools sockets after an abandoned call", async () => {
    let connections = 0;
    slowHeaders.on("connection", () => void connections++);

    const app = makeApp(true);
    await callSlowHeaders(app, "fetch");
    connections = 0;

    const recovery = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint({ origin: slowHeadersOrigin }),
        [TARGET_HEADER]: `${slowHeadersOrigin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(recovery.statusCode).toBe(200);

    const requests = 6;
    for (let i = 0; i < requests; i++) {
      const res = await app.inject({
        method: "POST",
        url: "/proxy",
        headers: {
          [INSTRUCTION_HEADER]: await mint({ origin: slowHeadersOrigin }),
          [TARGET_HEADER]: `${slowHeadersOrigin}/`,
          [METHOD_HEADER]: "GET",
        },
      });
      expect(res.statusCode).toBe(200);
    }
    expect(connections).toBeLessThan(requests + 1);

    app.server.closeAllConnections();
    await app.close();
  });
});

describe("egress /proxy — capability idle timeouts", () => {
  let stall: Server;
  let stallOrigin: string;

  beforeAll(async () => {
    stall = createServer((req, res) => {
      res.on("error", () => {});
      req.on("error", () => {});
      // Accept the request and send nothing — triggers undici headersTimeout.
    });
    await new Promise<void>((resolve) => stall.listen(0, "127.0.0.1", resolve));
    stallOrigin = `http://127.0.0.1:${(stall.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    stall.closeAllConnections();
    await new Promise<void>((resolve) => stall.close(() => resolve()));
  });

  function makeTimeoutApp(fetchMs: number, llmMs: number) {
    const config = {
      limits: { maxBodyBytes: 1024 * 1024, timeoutMs: fetchMs, llmTimeoutMs: llmMs },
      allowPrivate: true,
      allowInsecureConnection: true,
    } as EgressConfig;
    return buildApp({ config, resolver: fakeResolver, instructionKey: key, burnStore: null });
  }

  async function stallInject(
    app: ReturnType<typeof makeTimeoutApp>,
    capability: "fetch" | "llm",
  ): Promise<{ statusCode: number; json: () => unknown; elapsedMs: number }> {
    const started = Date.now();
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint({ origin: stallOrigin, capability }),
        [TARGET_HEADER]: `${stallOrigin}/hang`,
        [METHOD_HEADER]: "GET",
      },
    });
    return { statusCode: res.statusCode, json: () => res.json(), elapsedMs: Date.now() - started };
  }

  it("cuts non-LLM fetch calls at EGRESS_TIMEOUT_MS with upstream_timeout", async () => {
    const app = makeTimeoutApp(80, 5_000);
    const res = await stallInject(app, "fetch");
    expect(res.statusCode).toBe(502);
    expect(res.json()).toMatchObject({ code: "upstream_timeout" });
    await app.close();
  });

  it("bounds llm calls at EGRESS_LLM_TIMEOUT_MS, not the fetch timeout", async () => {
    const fetchApp = makeTimeoutApp(120, 5_000);
    const fetchRes = await stallInject(fetchApp, "fetch");
    await fetchApp.close();
    expect(fetchRes.statusCode).toBe(502);
    expect(fetchRes.json()).toMatchObject({ code: "upstream_timeout" });
    expect(fetchRes.elapsedMs).toBeLessThan(2_500);

    const llmApp = makeTimeoutApp(120, 800);
    const llmRes = await stallInject(llmApp, "llm");
    await llmApp.close();
    expect(llmRes.statusCode).toBe(502);
    expect(llmRes.json()).toMatchObject({ code: "upstream_timeout" });
    expect(llmRes.elapsedMs).toBeGreaterThan(500);
  });
});
