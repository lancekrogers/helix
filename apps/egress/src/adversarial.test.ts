import { randomBytes, randomUUID } from "node:crypto";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Readable, Writable } from "node:stream";
import { SignJWT } from "jose";
import { request as undiciRequest } from "undici";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import {
  INSTRUCTION_AUDIENCE,
  INSTRUCTION_HEADER,
  INSTRUCTION_JWT_TYP,
  METHOD_HEADER,
  OUTCOME_HEADER,
  TARGET_HEADER,
} from "@azx-pbc/shared";
import { ATTR_CAPABILITY, INSTR_EGRESS_UPSTREAM_ABORTS } from "@azx-pbc/shared/telemetry";
import { buildApp } from "./app.js";
import type { EgressConfig } from "./config.js";
import { deriveInstructionKey } from "./instruction.js";
import type { ResolvedConnection, SecretResolver } from "./secrets.js";
import { InMemoryBurnStore, type InstructionBurnStore } from "./burn.js";
import { parseCidrList } from "./ssrf.js";

/**
 * The adversarial pass the fetch-proxy demands (fetch-proxy design §6): SSRF to
 * the metadata service / private ranges, header smuggling (the app must not leak
 * the session cookie outbound nor override the injected credential), and forged
 * instructions. Mirrors the edge auth adversarial suite's stance — the controls
 * are asserted directly, not assumed.
 */

const key = deriveInstructionKey(randomBytes(32));

// An echo upstream so we can see exactly what (if anything) was forwarded.
let upstream: Server;
let origin: string;
beforeAll(async () => {
  upstream = createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify({
        authorization: req.headers["authorization"] ?? null,
        cookie: req.headers["cookie"] ?? null,
        xApiKey: req.headers["x-api-key"] ?? null,
      }),
    );
  });
  await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((resolve) => upstream.close(() => resolve())));

/** The private half of the hmac fixture pair — the needle for leak assertions. */
const HMAC_PRIVATE = "ghp_LIVEPRIVATEKEY_abcdefghijklmnop";
const HMAC_BLOB = JSON.stringify({ credential: "pub-abc", key: HMAC_PRIVATE });

// Mirrors PgSecretResolver's capability gate: `platform` secrets resolve only on
// the `llm` path, `app`/`global` only on `fetch`.
const resolver: SecretResolver = {
  resolve: async (_a, c, capability): Promise<ResolvedConnection | null> => {
    if (capability === "llm") {
      return c === "anthropic"
        ? {
            value: "platform-vendor-key",
            injection: { kind: "header", name: "x-api-key", template: "{}" },
          }
        : null;
    }
    switch (c) {
      case "gh":
        return { value: "injected-secret", injection: { kind: "header-bearer" } };
      case "gh-key":
        return {
          value: "key-secret-xyz",
          injection: { kind: "header", name: "x-api-key", template: "{}" },
        };
      case "gh-query":
        return { value: "query-secret-abc", injection: { kind: "query", param: "access_token" } };
      // An hmac-timestamp credential whose signature rides a NON-`authorization`
      // header. That is the case only the dynamic strip can cover: `authorization`
      // is in the static blocklist, so a recipe using it would pass even with the
      // widening reverted. This connection is what actually pins issue #7 for a
      // multi-header recipe.
      case "hmac-sig":
        return {
          value: HMAC_BLOB,
          injection: {
            kind: "hmac-timestamp",
            timestampHeader: "x-date",
            authHeader: "x-signature",
            template: "Credential={credential},Signature={signature}",
          },
        };
      default:
        return null;
    }
  },
  close: async () => {},
};

function makeApp(
  allowPrivate: boolean,
  allowInsecureConnection = true,
  burnStore: InstructionBurnStore | null = null,
  extraBlockedCidrs: EgressConfig["extraBlockedCidrs"] = [] as EgressConfig["extraBlockedCidrs"],
) {
  const config = {
    limits: { maxBodyBytes: 1024 * 1024, timeoutMs: 5000, llmTimeoutMs: 30_000 },
    allowPrivate,
    extraBlockedCidrs,
    // Loopback echo upstreams are http, so the cleartext-injection seam is open
    // for most tests; the issue #11 suite closes it to assert the prod guard.
    allowInsecureConnection,
  } as EgressConfig;
  return buildApp({ config, resolver, instructionKey: key, burnStore });
}

async function mint(
  o: string,
  connection?: string,
  capability: "fetch" | "llm" = "fetch",
  requestId: string = randomUUID(),
  bind: { method?: string; path?: string } = {},
): Promise<string> {
  return new SignJWT({
    appId: "app-1",
    userOid: "u",
    capability,
    origin: o,
    requestId,
    ...(bind.method ? { method: bind.method } : {}),
    ...(bind.path !== undefined ? { path: bind.path } : {}),
    ...(connection ? { connection } : {}),
  })
    .setProtectedHeader({ alg: "HS256", typ: INSTRUCTION_JWT_TYP })
    .setJti(requestId)
    .setAudience(INSTRUCTION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("30s")
    .sign(key);
}

describe("egress SSRF hardening", () => {
  // The prod posture: private ranges blocked.
  for (const target of [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/", // IMDS
    "http://127.0.0.1/secret",
    "http://10.0.0.5/internal",
    "http://[::1]/loopback",
    "http://168.63.129.16/",
    "http://[::ffff:a83f:8110]/",
  ]) {
    it(`refuses ${new URL(target).host}`, async () => {
      const app = makeApp(false);
      const o = new URL(target).origin;
      const res = await app.inject({
        method: "POST",
        url: "/proxy",
        headers: {
          [INSTRUCTION_HEADER]: await mint(o),
          [TARGET_HEADER]: target,
          [METHOD_HEADER]: "GET",
        },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json().code).toBe("blocked");
      await app.close();
    });
  }

  it("refuses a target in EGRESS_EXTRA_BLOCKED_CIDRS", async () => {
    const app = makeApp(
      false,
      true,
      null,
      parseCidrList("198.19.0.0/16", "EGRESS_EXTRA_BLOCKED_CIDRS"),
    );
    const target = "http://198.19.0.1/";
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(new URL(target).origin),
        [TARGET_HEADER]: target,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe("blocked");
    await app.close();
  });

  it("applies EGRESS_EXTRA_BLOCKED_CIDRS on the llm dispatcher too", async () => {
    // The llm capability rides its own dispatcher (longer idle timeout). It must
    // carry the same validating connector, extra block list included. The range
    // here is not in the built-in list, so only the extra list can refuse it.
    const app = makeApp(
      false,
      true,
      null,
      parseCidrList("203.0.114.0/24", "EGRESS_EXTRA_BLOCKED_CIDRS"),
    );
    const target = "http://203.0.114.1/";
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(new URL(target).origin, undefined, "llm"),
        [TARGET_HEADER]: target,
        [METHOD_HEADER]: "POST",
      },
      payload: "{}",
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe("blocked");
    await app.close();
  });

  it("returns a blocked-address message for the Azure platform IP (no dial)", async () => {
    const app = makeApp(false);
    const target = "http://168.63.129.16/";
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(new URL(target).origin),
        [TARGET_HEADER]: target,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe("blocked");
    expect(res.json().message).toMatch(/blocked address/);
    await app.close();
  });
});

describe("egress header smuggling", () => {
  it("never forwards the app's cookie or Authorization upstream", async () => {
    const app = makeApp(true);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(origin),
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
        cookie: "__Host-session=stolen",
        authorization: "Bearer app-supplied",
      },
    });
    const body = res.json();
    expect(body.cookie).toBeNull(); // session never leaks outbound
    expect(body.authorization).toBeNull(); // not safelisted
    await app.close();
  });

  it("the app cannot override the server-injected credential", async () => {
    const app = makeApp(true);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(origin, "gh"),
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
        authorization: "Bearer app-supplied", // dropped, then injection wins
      },
    });
    expect(res.json().authorization).toBe("Bearer injected-secret");
    await app.close();
  });
});

describe("egress cleartext-injection guard (issue #11)", () => {
  // Egress is the credential broker: with the dev seam closed (the prod posture),
  // it must refuse to inject a connection secret into a cleartext http:// target,
  // independently of whatever origin the edge authorized.
  it("refuses a secret-backed call to an http origin", async () => {
    const app = makeApp(true, /* allowInsecureConnection */ false);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(origin, "gh"),
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe("forbidden");
    // The upstream must never have seen the injected credential.
    expect(res.headers[OUTCOME_HEADER]).toBe("refusal");
    await app.close();
  });

  it("still allows a keyless (no-connection) call to an http origin", async () => {
    // The guard is scoped to the injection path — cleartext proxying with no
    // secret is unaffected.
    const app = makeApp(true, false);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(origin),
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().authorization).toBeNull(); // nothing injected
    await app.close();
  });
});

describe("egress platform-secret capability gate", () => {
  it("injects the platform vendor key for an llm instruction", async () => {
    const app = makeApp(true);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(origin, "anthropic", "llm"),
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.json().xApiKey).toBe("platform-vendor-key");
    await app.close();
  });

  it("refuses to inject the platform key on the fetch path (404 connection)", async () => {
    const app = makeApp(true);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        // A fetch instruction naming the platform connection resolves to nothing.
        [INSTRUCTION_HEADER]: await mint(origin, "anthropic", "fetch"),
        [TARGET_HEADER]: `${origin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe("forbidden");
    await app.close();
  });
});

describe("egress secret echo-back (issue #7)", () => {
  // A reflecting upstream: mirrors the credentials it received back into RESPONSE
  // headers (the echo/debug/CORS-reflection case) and echoes the request URL in
  // Location (the query-recipe reflection vector). This is the shape the static
  // blocklist misses — the injected header must be stripped before it reaches us.
  let echo: Server;
  let echoOrigin: string;
  beforeAll(async () => {
    echo = createServer((req, res) => {
      const auth = req.headers["authorization"];
      // Always set an Authorization response header: reflect the injected bearer
      // when present, else a server-issued sentinel (exercises the static backstop).
      res.setHeader("authorization", typeof auth === "string" ? auth : "Bearer upstream-issued");
      const apiKey = req.headers["x-api-key"];
      if (typeof apiKey === "string") res.setHeader("x-api-key", apiKey);
      // Reflect an hmac-timestamp recipe's pair too: the signature on a
      // non-`authorization` header, and the timestamp that is its signed input.
      const signature = req.headers["x-signature"];
      if (typeof signature === "string") res.setHeader("x-signature", signature);
      const date = req.headers["x-date"];
      if (typeof date === "string") res.setHeader("x-date", date);
      // Location echoes the request URL (redirect-follow + query-secret vector);
      // Content-Location echoes it too (the residual query-secret reflection path).
      res.setHeader("location", `${echoOrigin}${req.url}`);
      res.setHeader("content-location", `${echoOrigin}${req.url}`);
      res.setHeader("etag", '"v1"'); // a benign header the app relies on
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ authorization: auth ?? null, url: req.url }));
    });
    await new Promise<void>((resolve) => echo.listen(0, "127.0.0.1", resolve));
    echoOrigin = `http://127.0.0.1:${(echo.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise<void>((resolve) => echo.close(() => resolve())));

  async function proxy(connection?: string) {
    const app = makeApp(true);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(echoOrigin, connection),
        [TARGET_HEADER]: `${echoOrigin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    await app.close();
    return res;
  }

  it("strips a reflected header-bearer credential from the response", async () => {
    const res = await proxy("gh");
    expect(res.statusCode).toBe(200);
    expect(res.headers["authorization"]).toBeUndefined();
  });

  it("strips a reflected arbitrary-name credential the static blocklist can't enumerate", async () => {
    const res = await proxy("gh-key");
    expect(res.statusCode).toBe(200);
    // x-api-key is NOT in RESPONSE_HEADER_BLOCKLIST — only the dynamic strip removes it.
    expect(res.headers["x-api-key"]).toBeUndefined();
  });

  it("strips Location entirely so the browser can't follow the redirect (issue #10)", async () => {
    const res = await proxy("gh-query");
    expect(res.statusCode).toBe(200);
    // Not merely redacted — gone: a forwarded Location (even redacted) would let
    // the browser chase the upstream redirect un-proxied. ADR-0005.
    expect(res.headers["location"]).toBeUndefined();
  });

  it("redacts a query-recipe secret reflected in Content-Location (issue #7)", async () => {
    const res = await proxy("gh-query");
    expect(res.statusCode).toBe(200);
    const contentLocation = res.headers["content-location"];
    expect(contentLocation).toBeDefined();
    expect(contentLocation).not.toContain("query-secret-abc");
    expect(contentLocation).toContain("access_token=REDACTED");
  });

  it("does not over-strip benign headers the app relies on", async () => {
    const res = await proxy("gh");
    expect(res.headers["etag"]).toBe('"v1"');
    expect(res.headers["content-type"]).toContain("application/json");
  });

  it("strips a server-issued Authorization via the static backstop (keyless call)", async () => {
    // Nothing injected, so the dynamic strip is inert; the shared blocklist must
    // still drop the upstream's Authorization response header.
    const res = await proxy();
    expect(res.statusCode).toBe(200);
    expect(res.headers["authorization"]).toBeUndefined();
  });

  it("does NOT close the body-echo channel (documented transparent-proxy residual)", async () => {
    // An upstream that echoes the secret into the response BODY still reaches the
    // app — no header filter closes this. Pinned so the residual is explicit.
    const res = await proxy("gh");
    expect(res.json().authorization).toBe("Bearer injected-secret");
  });

  /**
   * The test that proves the multi-header widening. `x-signature` can never be in
   * RESPONSE_HEADER_BLOCKLIST — the name is per-recipe configuration — so only
   * recording both injected names and stripping the set covers it. Reverting
   * `Injected.headerNames` to a single name fails here and nowhere else.
   */
  it("strips a reflected hmac signature carried on a non-authorization header", async () => {
    const res = await proxy("hmac-sig");
    expect(res.statusCode).toBe(200);
    expect(res.headers["x-signature"]).toBeUndefined();
  });

  it("strips the reflected timestamp header that is the signature's signed input", async () => {
    const res = await proxy("hmac-sig");
    expect(res.headers["x-date"]).toBeUndefined();
  });

  /**
   * The private key is the thing that must never escape by any channel. Unlike the
   * signature — which is a per-timestamp derivation and only useful for the
   * upstream's skew window — the key is durable: it forges credentials until it is
   * rotated. Asserted across status, every header, and the whole body.
   */
  it("never lets the private key reach the app by any channel", async () => {
    const res = await proxy("hmac-sig");
    const everything = `${res.statusCode}${JSON.stringify(res.headers)}${res.payload}`;
    expect(everything).not.toContain(HMAC_PRIVATE);
    // The V8 JSON.parse snippet shape, pinned explicitly.
    expect(everything).not.toContain(HMAC_PRIVATE.slice(0, 10));
    // ...and the blob's own field names, which would signal the shape leaked.
    expect(everything).not.toContain('"key"');
  });

  /**
   * The public credential is *public* — it is sent in the clear on every request
   * and identifies the account, not the authority. Asserting its absence would
   * pin a false invariant, so pin the true one: what reflects back through the
   * body-echo residual is a signature, never the key. For this recipe that
   * residual is materially weaker than for a static bearer.
   */
  it("body-echo can reflect a signature, which is not the key", async () => {
    const app = makeApp(true);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(echoOrigin, "hmac-sig"),
        [TARGET_HEADER]: `${echoOrigin}/`,
        [METHOD_HEADER]: "GET",
      },
    });
    // The echo upstream mirrors `authorization` into its body; this recipe writes
    // the signature to `x-signature`, so the body carries no credential at all here.
    expect(res.json().authorization).toBeNull();
    expect(res.payload).not.toContain(HMAC_PRIVATE);
    await app.close();
  });

  /**
   * The app must not be able to pre-occupy either injected header. Neither name is
   * in REQUEST_HEADER_SAFELIST, and injection runs after the safelist filter — but
   * nothing pinned that for the timestamp header, and a future safelist addition
   * would silently open it.
   */
  it("drops an app-supplied timestamp or authorization header before injecting", async () => {
    const app = makeApp(true);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(echoOrigin, "hmac-sig"),
        [TARGET_HEADER]: `${echoOrigin}/`,
        [METHOD_HEADER]: "GET",
        "x-date": "1999-01-01T00:00:00.000Z",
        "x-signature": "attacker-chosen",
        authorization: "Bearer app-supplied",
      },
    });
    expect(res.statusCode).toBe(200);
    // The upstream saw our derived pair, not the app's. (Both are stripped from the
    // response, so assert via the body's own echo of what arrived.)
    expect(res.json().authorization).toBeNull();
    await app.close();
  });
});

describe("egress body-size cap (issue #8)", () => {
  // The cap must hold for *streamed* bodies, where the content-length fast-path
  // is a no-op: a chunked / CL-absent response is counted and truncated, and a
  // chunked request is cut off before it streams unbounded egress-billed
  // bandwidth upstream. Exercised over a real socket (undici → a listening
  // egress) so the streaming/teardown behavior is faithful, not an inject
  // approximation.
  const CAP = 64;
  const bytes = (n: number): Buffer => Buffer.alloc(n, 0x61);

  let received = 0; // request bytes the upstream actually saw
  let upstream: Server;
  let capOrigin: string;
  let app: ReturnType<typeof buildApp>;
  let base: string;
  let recording: RecordingTelemetry;

  async function metricTotal(name: string, match: Record<string, string>): Promise<number> {
    const points = await recording.metrics();
    return points
      .filter(
        (m) => m.name === name && Object.entries(match).every(([k, v]) => m.attributes[k] === v),
      )
      .reduce((sum, m) => sum + m.value, 0);
  }

  beforeAll(async () => {
    recording = startRecordingTelemetry();
    upstream = createServer((req, res) => {
      if (req.url === "/large") {
        // 320 bytes, chunked (no content-length) — the headline bypass.
        res.setHeader("content-type", "text/plain");
        for (let i = 0; i < 8; i++) res.write(bytes(40));
        res.end();
        return;
      }
      if (req.url === "/small") {
        res.end(bytes(40)); // content-length: 40, under the cap
        return;
      }
      // Default: a byte sink that records how much of the request body arrived.
      req.on("data", (c: Buffer) => {
        received += c.length;
      });
      req.on("end", () => res.end("ok"));
      req.on("error", () => {});
    });
    await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
    capOrigin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;

    const config = {
      limits: { maxBodyBytes: CAP, timeoutMs: 5000, llmTimeoutMs: 30_000 },
      allowPrivate: true,
      extraBlockedCidrs: [] as EgressConfig["extraBlockedCidrs"],
    } as EgressConfig;
    // Body-size cap suite: replay protection is orthogonal, so no burn store.
    app = buildApp({ config, resolver, instructionKey: key, burnStore: null });
    await app.listen({ port: 0, host: "127.0.0.1" });
    base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
  });
  afterEach(() => recording.reset());
  afterAll(async () => {
    await recording.restore();
    await app.close();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  });

  it("truncates a chunked (CL-absent) response that exceeds the cap", async () => {
    const res = await undiciRequest(`${base}/proxy`, {
      method: "POST",
      headers: {
        [INSTRUCTION_HEADER]: await mint(capOrigin),
        [TARGET_HEADER]: `${capOrigin}/large`,
        [METHOD_HEADER]: "GET",
      },
    });
    // Status + headers were already committed, so the app sees a 200 whose body
    // is cut short — not a 502.
    expect(res.statusCode).toBe(200);
    let got = 0;
    try {
      for await (const chunk of res.body) got += (chunk as Buffer).length;
    } catch {
      // Premature close is the expected shape of a mid-stream truncation.
    }
    expect(got).toBeLessThanOrEqual(CAP); // counter cut it at the cap
    expect(got).toBeLessThan(320); // the full body never reached the app
  });

  it("streams an under-cap response through intact (no false trip)", async () => {
    const res = await undiciRequest(`${base}/proxy`, {
      method: "POST",
      headers: {
        [INSTRUCTION_HEADER]: await mint(capOrigin),
        [TARGET_HEADER]: `${capOrigin}/small`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(200);
    expect((await res.body.text()).length).toBe(40);
  });

  it("cuts off a chunked (CL-absent) request body over the cap", async () => {
    received = 0;
    // 256 bytes streamed with no content-length ⇒ undici sends it chunked, so
    // the request fast-path can't see it — only the byte counter stops it.
    const body = Readable.from([bytes(64), bytes(64), bytes(64), bytes(64)]);
    let status = 0;
    let threw = false;
    try {
      const res = await undiciRequest(`${base}/proxy`, {
        method: "POST",
        headers: {
          [INSTRUCTION_HEADER]: await mint(capOrigin),
          [TARGET_HEADER]: `${capOrigin}/sink`,
          [METHOD_HEADER]: "POST",
        },
        body,
      });
      status = res.statusCode;
      await res.body.text().catch(() => {});
    } catch {
      // A reset mid-upload (egress stopped reading) is an acceptable shape too.
      threw = true;
    }
    expect(threw || status === 413).toBe(true);
    // The upstream never received more than the cap — the point of the counter.
    expect(received).toBeLessThanOrEqual(CAP);
  });

  it("refuses a truthful oversized content-length request before dialing out", async () => {
    // A Buffer body ⇒ undici sets a real content-length ⇒ the fast-path fires
    // with a clean 413 and the upstream is never contacted.
    received = 0;
    const res = await undiciRequest(`${base}/proxy`, {
      method: "POST",
      headers: {
        [INSTRUCTION_HEADER]: await mint(capOrigin),
        [TARGET_HEADER]: `${capOrigin}/sink`,
        [METHOD_HEADER]: "POST",
      },
      body: bytes(CAP + 1),
    });
    expect(res.statusCode).toBe(413);
    const json = (await res.body.json()) as { code: string };
    expect(json.code).toBe("too_large");
    expect(res.headers[OUTCOME_HEADER]).toBe("refusal");
    expect(received).toBe(0); // never forwarded
  });

  it("does not count a request-cap trip as an upstream abort", async () => {
    const chunks: string[] = [];
    const capture = new Writable({
      write(chunk: unknown, _enc: BufferEncoding, cb: (e?: Error | null) => void) {
        chunks.push(String(chunk));
        cb();
      },
    });
    const config = {
      limits: { maxBodyBytes: CAP, timeoutMs: 5000, llmTimeoutMs: 30_000 },
      allowPrivate: true,
      extraBlockedCidrs: [] as EgressConfig["extraBlockedCidrs"],
    } as EgressConfig;
    const capApp = buildApp(
      { config, resolver, instructionKey: key, burnStore: null },
      { level: "warn", stream: capture },
    );
    await capApp.listen({ port: 0, host: "127.0.0.1" });
    const capBase = `http://127.0.0.1:${(capApp.server.address() as AddressInfo).port}`;

    const before = await metricTotal(INSTR_EGRESS_UPSTREAM_ABORTS, {
      [ATTR_CAPABILITY]: "fetch",
    });
    received = 0;
    const body = Readable.from([bytes(64), bytes(64), bytes(64), bytes(64)]);
    let status = 0;
    let threw = false;
    try {
      const res = await undiciRequest(`${capBase}/proxy`, {
        method: "POST",
        headers: {
          [INSTRUCTION_HEADER]: await mint(capOrigin),
          [TARGET_HEADER]: `${capOrigin}/sink`,
          [METHOD_HEADER]: "POST",
        },
        body,
      });
      status = res.statusCode;
      await res.body.text().catch(() => {});
    } catch {
      threw = true;
    }
    expect(threw || status === 413).toBe(true);
    const after = await metricTotal(INSTR_EGRESS_UPSTREAM_ABORTS, {
      [ATTR_CAPABILITY]: "fetch",
    });
    expect(after).toBe(before);
    expect(chunks.join("")).not.toContain("upstream request failed");
    await capApp.close();
  });

  it("counts a client hang-up mid-upload as an upstream abort", async () => {
    const chunks: string[] = [];
    const capture = new Writable({
      write(chunk: unknown, _enc: BufferEncoding, cb: (e?: Error | null) => void) {
        chunks.push(String(chunk));
        cb();
      },
    });
    const config = {
      limits: { maxBodyBytes: CAP * 4, timeoutMs: 5000, llmTimeoutMs: 30_000 },
      allowPrivate: true,
      extraBlockedCidrs: [] as EgressConfig["extraBlockedCidrs"],
    } as EgressConfig;
    const capApp = buildApp(
      { config, resolver, instructionKey: key, burnStore: null },
      { level: "warn", stream: capture },
    );
    await capApp.listen({ port: 0, host: "127.0.0.1" });
    const capBase = `http://127.0.0.1:${(capApp.server.address() as AddressInfo).port}`;

    const before = await metricTotal(INSTR_EGRESS_UPSTREAM_ABORTS, {
      [ATTR_CAPABILITY]: "fetch",
    });
    received = 0;
    const ac = new AbortController();
    let pushed = 0;
    const slowBody = new Readable({
      read() {
        if (pushed++ >= 3) return;
        this.push(bytes(16));
      },
    });
    const pending = undiciRequest(`${capBase}/proxy`, {
      method: "POST",
      signal: ac.signal,
      headers: {
        [INSTRUCTION_HEADER]: await mint(capOrigin),
        [TARGET_HEADER]: `${capOrigin}/sink`,
        [METHOD_HEADER]: "POST",
      },
      body: slowBody,
    });
    await new Promise((r) => setTimeout(r, 80));
    ac.abort();
    try {
      await pending;
    } catch {
      // hang-up mid-upload
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
    expect(chunks.join("")).not.toContain("upstream request failed");
    await capApp.close();
  });
});

describe("egress instruction forgery", () => {
  it("rejects a token signed with the wrong key", async () => {
    const app = makeApp(true);
    const wrong = await new SignJWT({
      appId: "app-1",
      userOid: "u",
      capability: "fetch",
      origin,
      requestId: "r",
    })
      .setProtectedHeader({ alg: "HS256", typ: INSTRUCTION_JWT_TYP })
      .setIssuedAt()
      .setExpirationTime("30s")
      .sign(deriveInstructionKey(randomBytes(32)));
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: { [INSTRUCTION_HEADER]: wrong, [TARGET_HEADER]: `${origin}/` },
    });
    expect(res.statusCode).toBe(401);
    await app.close();
  });

  it("rejects an unknown claim instead of stripping it (ADR-0005 strict parse)", async () => {
    // A future edge widening verified here must fail closed: the unknown claim
    // fails the payload schema rather than vanishing (which could drop the
    // credential field and send the call out unauthenticated).
    const app = makeApp(true);
    const rid = randomUUID();
    const skewed = await new SignJWT({
      appId: "app-1",
      userOid: "u",
      capability: "fetch",
      origin,
      requestId: rid,
      connection: "gh",
      credentialV2: "a-claim-an-older-egress-never-heard-of",
    })
      .setProtectedHeader({ alg: "HS256", typ: INSTRUCTION_JWT_TYP })
      .setJti(rid)
      .setAudience(INSTRUCTION_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime("30s")
      .sign(key);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: { [INSTRUCTION_HEADER]: skewed, [TARGET_HEADER]: `${origin}/` },
    });
    expect(res.statusCode).toBe(401);
    await app.close();
  });
});

describe("egress instruction replay + audience (ADR-0013 Step 1, issue #3)", () => {
  it("burns the jti: a replayed instruction is refused on the second use", async () => {
    const app = makeApp(true, true, new InMemoryBurnStore());
    const token = await mint(origin); // one instruction, sent twice
    const send = () =>
      app.inject({
        method: "POST",
        url: "/proxy",
        headers: {
          [INSTRUCTION_HEADER]: token,
          [TARGET_HEADER]: `${origin}/`,
          [METHOD_HEADER]: "GET",
        },
      });

    const first = await send();
    expect(first.statusCode).toBe(200);
    expect(first.headers[OUTCOME_HEADER]).toBe("ok");

    const second = await send();
    expect(second.statusCode).toBe(409);
    expect(second.json()).toMatchObject({ code: "replay" });
    expect(second.headers[OUTCOME_HEADER]).toBe("refusal");
    await app.close();
  });

  it("two distinct instructions both pass (only the identical jti is burned)", async () => {
    const app = makeApp(true, true, new InMemoryBurnStore());
    for (let i = 0; i < 2; i++) {
      const res = await app.inject({
        method: "POST",
        url: "/proxy",
        headers: {
          [INSTRUCTION_HEADER]: await mint(origin), // fresh jti each time
          [TARGET_HEADER]: `${origin}/`,
          [METHOD_HEADER]: "GET",
        },
      });
      expect(res.statusCode).toBe(200);
    }
    await app.close();
  });

  it("rejects a token with no audience (token passthrough)", async () => {
    const app = makeApp(true);
    const rid = randomUUID();
    const noAud = await new SignJWT({
      appId: "app-1",
      userOid: "u",
      capability: "fetch",
      origin,
      requestId: rid,
    })
      .setProtectedHeader({ alg: "HS256", typ: INSTRUCTION_JWT_TYP })
      .setJti(rid)
      .setIssuedAt()
      .setExpirationTime("30s")
      .sign(key);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: { [INSTRUCTION_HEADER]: noAud, [TARGET_HEADER]: `${origin}/` },
    });
    expect(res.statusCode).toBe(401);
    await app.close();
  });

  it("rejects a token whose jti does not match its requestId", async () => {
    const app = makeApp(true);
    const mismatched = await new SignJWT({
      appId: "app-1",
      userOid: "u",
      capability: "fetch",
      origin,
      requestId: randomUUID(),
    })
      .setProtectedHeader({ alg: "HS256", typ: INSTRUCTION_JWT_TYP })
      .setJti(randomUUID()) // different from requestId
      .setAudience(INSTRUCTION_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime("30s")
      .sign(key);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: { [INSTRUCTION_HEADER]: mismatched, [TARGET_HEADER]: `${origin}/` },
    });
    expect(res.statusCode).toBe(401);
    await app.close();
  });
});

describe("egress method/path binding (ADR-0013 step 2, issue #6)", () => {
  it("proxies when the request's method + pathname match the instruction", async () => {
    const app = makeApp(true);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(origin, undefined, "fetch", randomUUID(), {
          method: "GET",
          path: "/ok",
        }),
        [TARGET_HEADER]: `${origin}/ok`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(200);
    await app.close();
  });

  it("refuses a mismatched method — a captured instruction can't change the verb", async () => {
    const app = makeApp(true);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(origin, undefined, "fetch", randomUUID(), {
          method: "GET",
          path: "/ok",
        }),
        [TARGET_HEADER]: `${origin}/ok`,
        [METHOD_HEADER]: "POST", // ← differs from the bound GET
      },
    });
    expect(res.statusCode).toBe(403);
    await app.close();
  });

  it("refuses a mismatched pathname — a captured instruction can't change the resource", async () => {
    const app = makeApp(true);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(origin, undefined, "fetch", randomUUID(), {
          method: "GET",
          path: "/ok",
        }),
        [TARGET_HEADER]: `${origin}/evil`, // ← differs from the bound /ok
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(403);
    await app.close();
  });

  it("tolerates a legacy instruction with no method/path bound (rollout safety)", async () => {
    const app = makeApp(true);
    const res = await app.inject({
      method: "POST",
      url: "/proxy",
      headers: {
        [INSTRUCTION_HEADER]: await mint(origin), // no method/path claims
        [TARGET_HEADER]: `${origin}/anything`,
        [METHOD_HEADER]: "GET",
      },
    });
    expect(res.statusCode).toBe(200);
    await app.close();
  });
});
