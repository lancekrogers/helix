import { randomBytes } from "node:crypto";
import { Readable } from "node:stream";
import { request as undiciRequest } from "undici";
import { describe, expect, it, vi } from "vitest";
import { startRecordingTelemetry } from "@azx-pbc/telemetry/testing";
import { INSTR_GATEWAY_ADMISSION_DENIED } from "@azx-pbc/shared/telemetry";
import type { FastifyInstance } from "fastify";
import { type JWTPayload, jwtVerify } from "jose";
import { INSTRUCTION_AUDIENCE, INSTRUCTION_JWT_TYP } from "@azx-pbc/shared";
import { buildApp } from "../app.js";
import type { ProxiedOriginCredential } from "../registry/projection.js";
import { testAuthConfig, testEdgeConfig } from "../test/config.js";
import { until, withServer } from "../test/socket.js";
import {
  FakeBlobReader,
  FakeOidcClient,
  FakeRegistry,
  FakeSessionStore,
  FakeUsageStore,
  registryEntry,
} from "../test/fakes.js";
import { deriveInstructionKey } from "./instruction.js";
import { MODEL_MAX, PATH_MAX } from "./usage.js";
import type { EgressProvider, EgressRequest, EgressResponse } from "./egressProvider.js";
import { InMemoryLeaseStore, type AcquireResult, type LeaseStore } from "./leaseStore.js";

/**
 * The `/_api/fetch` policy plane (fetch-proxy design §7): gate + CSRF, the
 * manifest proxy-origin allowlist, the per-app request budget, attested-
 * instruction minting, and metering. A fake egress captures what the edge
 * forwards; the egress service itself is tested in apps/egress.
 */

const APP_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PREFIX = "apps/a/1/";
const HOST = { host: "demo.local.helix.azxlabs.io" };
const ORIGIN = "https://demo.local.helix.azxlabs.io:8080";
const secret = randomBytes(32);
const key = deriveInstructionKey(secret);

/** undici rejects an in-flight request with this the moment its signal fires. */
function abortError(): Error {
  const err = new Error("This operation was aborted");
  err.name = "AbortError";
  return err;
}

class FakeEgress implements EgressProvider {
  calls: EgressRequest[] = [];
  outcome = "ok";
  /** The status the proxied response carries (the upstream's, verbatim). */
  status = 200;
  /** When set, the response body egress "returns" — used to exercise the cap. */
  responseBody: Readable | null = null;
  /** Extra headers the fake upstream response carries (merged over the default). */
  responseHeaders: Record<string, string> = {};
  /** When set, the request body is fully drained so tests can measure its size. */
  drainRequest = false;
  drainedBytes = 0;
  /**
   * Hold the call open this long before answering, standing in for an upstream
   * that takes real time. At the default 0 the response is already resolved
   * before the edge could possibly abort, so a self-abort would be invisible —
   * any test asserting on abort behaviour has to set this.
   */
  delayMs = 0;
  /** Set when the edge's signal fired while this call was still in flight. */
  abortedDuringCall = false;

  async proxy(req: EgressRequest): Promise<EgressResponse> {
    this.calls.push(req);
    // Watch from the moment the call starts, not just during the delay window:
    // a client that hangs up mid-upload aborts while we are still draining, and
    // that has to be observable too.
    let settled = false;
    if (req.signal.aborted) this.abortedDuringCall = true;
    else {
      req.signal.addEventListener(
        "abort",
        () => {
          // Only while in flight: once we have answered, the edge tearing the
          // request down is ordinary completion, not a cancelled call.
          if (!settled) this.abortedDuringCall = true;
        },
        { once: true },
      );
    }
    if (this.drainRequest && req.body && typeof req.body !== "string") {
      for await (const chunk of req.body as Readable) this.drainedBytes += (chunk as Buffer).length;
    }
    if (this.delayMs > 0) await this.#holdOpen(req.signal);
    settled = true;
    return {
      status: this.status,
      headers: { "content-type": "application/json", ...this.responseHeaders },
      body: this.responseBody ?? Readable.from([Buffer.from(JSON.stringify({ ok: true }))]),
      outcome: this.outcome,
    };
  }

  /**
   * Mirror undici's contract, which is the whole point of the fake here: a call
   * in flight rejects with an AbortError as soon as its signal fires. A fake
   * that ignored the signal would answer 200 even while the edge was aborting
   * it, and the bug this guards against would pass.
   */
  #holdOpen(signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      if (signal.aborted) {
        reject(abortError());
        return;
      }
      const onAbort = (): void => {
        clearTimeout(timer);
        reject(abortError());
      };
      const timer = setTimeout(() => {
        signal.removeEventListener("abort", onAbort);
        resolve();
      }, this.delayMs);
      signal.addEventListener("abort", onAbort, { once: true });
    });
  }

  async close(): Promise<void> {}
}

interface FetchEdge {
  app: FastifyInstance;
  egress: FakeEgress;
  usage: FakeUsageStore;
  leases: InMemoryLeaseStore;
}

const FETCH_PATH = "/_api/fetch/https://api.github.com/users/octocat";

function buildFetchEdge(
  opts: {
    connections?: Map<string, ProxiedOriginCredential>;
    requestsPerDay?: number | null;
    withEgress?: boolean;
    maxBodyBytes?: number;
    maxAppInFlight?: number;
    leases?: LeaseStore;
  } = {},
): FetchEdge {
  const egress = new FakeEgress();
  const usage = new FakeUsageStore();
  const leases = opts.leases instanceof InMemoryLeaseStore ? opts.leases : new InMemoryLeaseStore();
  const connections =
    opts.connections ??
    new Map<string, ProxiedOriginCredential>([
      ["https://api.github.com", { kind: "keyless" }],
      ["https://api.stripe.com", { kind: "secret", connection: "stripe" }],
    ]);
  const app = buildApp({
    config: testEdgeConfig({
      auth: testAuthConfig(),
      allowUnauthenticated: false,
      fetch: {
        egressUrl: null,
        instructionSecret: null,
        timeoutMs: 30_000,
        maxBodyBytes: opts.maxBodyBytes ?? 10 * 1024 * 1024,
        maxAppInFlight: opts.maxAppInFlight ?? 0,
      },
    }),
    registry: new FakeRegistry([
      registryEntry({
        appId: APP_ID,
        slug: "demo",
        blobPrefix: PREFIX,
        visibilityMode: "public", // anonymous caller — no session needed
        fetch: { connections, requestsPerDay: opts.requestsPerDay ?? null, shim: false },
      }),
    ]),
    blob: new FakeBlobReader(),
    sessions: new FakeSessionStore(),
    oidc: new FakeOidcClient(),
    usage,
    egress: opts.withEgress === false ? null : egress,
    instructionKey: opts.withEgress === false ? null : key,
    leases,
  });
  return { app, egress, usage, leases };
}

async function decode(token: string): Promise<JWTPayload> {
  const { payload } = await jwtVerify(token, key, { typ: INSTRUCTION_JWT_TYP });
  return payload;
}

describe("/_api/fetch", () => {
  it("proxies a keyless allowlisted origin, mints an instruction, meters it", async () => {
    const { app, egress, usage } = buildFetchEdge();
    const res = await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.github.com/users/octocat",
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true });
    expect(egress.calls).toHaveLength(1);
    expect(egress.calls[0]!.target).toBe("https://api.github.com/users/octocat");
    const claims = await decode(egress.calls[0]!.instruction);
    expect(claims.origin).toBe("https://api.github.com");
    expect(claims.connection).toBeUndefined();
    expect(claims.userOid).toBe("anon");
    // Regression: a keyless call is not delegated — no provider ref
    // and no caller kind rides it, so the minted payload is unchanged.
    expect(claims.provider).toBeUndefined();
    expect(claims.userKind).toBeUndefined();
    // Instruction carries the aud + one-time jti (== requestId) egress asserts.
    expect(claims.aud).toBe(INSTRUCTION_AUDIENCE);
    expect(claims.jti).toBe(claims.requestId);
    expect(typeof claims.jti).toBe("string");
    expect(usage.records).toContainEqual(
      expect.objectContaining({
        capability: "fetch",
        model: "https://api.github.com",
        path: "/users/octocat",
        method: "GET",
        outcome: "ok",
      }),
    );
    await app.close();
  });

  it("names the connection in the instruction for a secret-bound origin", async () => {
    const { app, egress } = buildFetchEdge();
    const res = await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.stripe.com/v1/charges",
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(res.statusCode).toBe(200);
    const claims = await decode(egress.calls[0]!.instruction);
    expect(claims.connection).toBe("stripe");
    // Regression: a secret-backed call is not delegated — no provider
    // ref and no caller kind rides it, so the minted payload is unchanged.
    expect(claims.provider).toBeUndefined();
    expect(claims.userKind).toBeUndefined();
    await app.close();
  });

  /**
   * Delegated origins: a provider-bound origin passes the same
   * allowlist gate a secret-bound one does — the gate ORDER is unchanged — and
   * the minted instruction carries the provider ref (never a connection name)
   * plus the caller's principal kind, which is mandatory on a
   * delegated instruction. The egress outcome vocabulary's delegated words
   * ledger per the outcome map's granularity.
   */
  describe("delegated origins", () => {
    /** One provider-bound origin, as an approved binding projects it. */
    function delegatedConnections(): Map<string, ProxiedOriginCredential> {
      return new Map([
        ["https://api.github.com", { kind: "provider", provider: "github-app", required: false }],
        ["https://api.stripe.com", { kind: "secret", connection: "stripe" }],
      ]);
    }

    it("mints a delegated instruction carrying the provider ref and no connection name", async () => {
      const { app, egress, usage } = buildFetchEdge({ connections: delegatedConnections() });
      const res = await app.inject({
        method: "GET",
        url: "/_api/fetch/https://api.github.com/users/octocat",
        headers: { ...HOST, origin: ORIGIN },
      });
      expect(res.statusCode).toBe(200);
      expect(egress.calls).toHaveLength(1);
      const claims = await decode(egress.calls[0]!.instruction);
      expect(claims.provider).toBe("github-app");
      // Exactly one credential source rides — and the edge
      // holds no secret for this origin to name anyway.
      expect(claims.connection).toBeUndefined();
      // The caller's kind is mandatory on a delegated instruction.
      // This caller is the public app's anonymous visitor — egress refuses it
      // BY KIND, so the edge must attest `anon`, never leave egress to
      // infer it from userOid's shape.
      expect(claims.userKind).toBe("anon");
      expect(claims.userOid).toBe("anon");
      // Delegated calls ride the existing metering and identity attribution
      // unchanged — no new user-dimension machinery.
      expect(usage.records).toContainEqual(
        expect.objectContaining({
          capability: "fetch",
          model: "https://api.github.com",
          outcome: "ok",
          userOid: "anon",
          userKind: "anon",
        }),
      );
      await app.close();
    });

    it("refuses an unapproved binding by the existing forbidden path", async () => {
      // An unapproved binding never reaches the projection's grant map — the
      // portal's approval chain gates the manifest before it becomes effective
      // (the edge never evaluates provider state; approval/binding
      // presence is all it sees, never liveness). The origin is simply not a
      // proxied origin here, so exactly the non-granted path answers.
      const { app, egress, usage } = buildFetchEdge({ connections: delegatedConnections() });
      const res = await app.inject({
        method: "GET",
        url: "/_api/fetch/https://api.notion.com/v1/users",
        headers: { ...HOST, origin: ORIGIN },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json().code).toBe("forbidden");
      expect(egress.calls).toHaveLength(0);
      expect(usage.records).toContainEqual(
        expect.objectContaining({
          capability: "fetch",
          model: "https://api.notion.com",
          outcome: "forbidden",
          statusCode: 403,
        }),
      );
      await app.close();
    });

    it("ledgers an egress connection_required under its own label, consuming budget", async () => {
      // Criterion 50: "user not connected" must stay distinguishable from
      // policy refusal in the metered record. The row also consumes the daily
      // fetch budget (fetchRequestsToday excludes only the pre-egress
      // refusals) — asserted here so the choice cannot silently flip.
      const { app, egress, usage } = buildFetchEdge({ connections: delegatedConnections() });
      egress.outcome = "connection_required";
      egress.status = 403;
      const res = await app.inject({
        method: "GET",
        url: "/_api/fetch/https://api.github.com/users/octocat",
        headers: { ...HOST, origin: ORIGIN },
      });
      expect(res.statusCode).toBe(403);
      const record = usage.records.find((r) => r.capability === "fetch");
      expect(record?.outcome).toBe("connection_required");
      expect(record?.outcome).not.toBe("refusal");
      expect(await usage.fetchRequestsToday()).toBe(1);
      await app.close();
    });

    it("ledgers provider-shaped refusals as refusal and temporary failure as error", async () => {
      // The ledger's outcome granularity: only `connection_required` gets a
      // label of its own; `provider_unavailable` / `provider_misconfigured`
      // meter as `refusal`; a temporary failure meters as `error`.
      const { app, egress, usage } = buildFetchEdge({ connections: delegatedConnections() });
      const call = () =>
        app.inject({
          method: "GET",
          url: "/_api/fetch/https://api.github.com/users/octocat",
          headers: { ...HOST, origin: ORIGIN },
        });
      const outcomeOf = () => usage.records.filter((r) => r.capability === "fetch").at(-1)?.outcome;

      egress.outcome = "provider_unavailable";
      egress.status = 503;
      expect((await call()).statusCode).toBe(503);
      expect(outcomeOf()).toBe("refusal");

      egress.outcome = "provider_misconfigured";
      egress.status = 502;
      expect((await call()).statusCode).toBe(502);
      expect(outcomeOf()).toBe("refusal");

      // The delegated temporary-failure shape: egress fails the call as its
      // existing upstream_error class (502, outcome `error`).
      egress.outcome = "error";
      egress.status = 502;
      expect((await call()).statusCode).toBe(502);
      expect(outcomeOf()).toBe("error");
      await app.close();
    });
  });

  it("preserves path and query in the forwarded target", async () => {
    const { app, egress } = buildFetchEdge();
    await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.github.com/search?q=helix&page=2",
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(egress.calls[0]!.target).toBe("https://api.github.com/search?q=helix&page=2");
    await app.close();
  });

  it("meters the path but never the target's query string", async () => {
    // The query is forwarded upstream (above) and deliberately NOT persisted: an
    // app-chosen third-party URL routinely carries a live credential there, and
    // the ledger has no DELETE grant for any role. Same line the request-log
    // serializer draws (`redactFetchTarget`).
    const { app, usage } = buildFetchEdge();
    await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.github.com/search?api_key=sk-live-must-not-persist",
      headers: { ...HOST, origin: ORIGIN },
    });
    const record = usage.records.find((r) => r.capability === "fetch");
    expect(record?.path).toBe("/search");
    expect(JSON.stringify(usage.records)).not.toContain("sk-live-must-not-persist");
    await app.close();
  });

  it("caps the origin it records for an absurd host", async () => {
    // `model` carries `target.origin` on a fetch row, and on a denial that
    // origin is whatever the app put in the URL — bounded only by Node's
    // maxHeaderSize until the store clamps it. Asserted through the fake, which
    // shares `clampRecord` with the real store.
    const { app, usage } = buildFetchEdge();
    await app.inject({
      method: "GET",
      url: `/_api/fetch/https://${"h".repeat(MODEL_MAX + 300)}.example.com/x`,
      headers: { ...HOST, origin: ORIGIN },
    });
    const record = usage.records.find((r) => r.capability === "fetch");
    expect(record?.model).toHaveLength(MODEL_MAX + 1);
    expect(record?.errorDetail?.length).toBeLessThanOrEqual(301);
    await app.close();
  });

  it("caps a pathological path rather than storing it whole", async () => {
    const { app, usage } = buildFetchEdge();
    await app.inject({
      method: "GET",
      url: `/_api/fetch/https://api.github.com/${"a".repeat(PATH_MAX + 200)}`,
      headers: { ...HOST, origin: ORIGIN },
    });
    const record = usage.records.find((r) => r.capability === "fetch");
    expect(record?.path).toHaveLength(PATH_MAX + 1);
    expect(record?.path?.endsWith("…")).toBe(true);
    await app.close();
  });

  it("refuses an origin that is not a proxied origin (egress untouched)", async () => {
    const { app, egress, usage } = buildFetchEdge();
    const res = await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.evil.com/steal",
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBe("forbidden");
    expect(egress.calls).toHaveLength(0);
    // The denial is the most audit-interesting event on this surface, and it
    // used to leave no ledger trace at all.
    expect(usage.records).toContainEqual(
      expect.objectContaining({
        capability: "fetch",
        model: "https://api.evil.com",
        path: "/steal",
        method: "GET",
        outcome: "forbidden",
        statusCode: 403,
      }),
    );
    await app.close();
  });

  it("caps how many denials it meters, while still refusing every one", async () => {
    // The denial write is the one ledger append no other gate bounds: the
    // per-IP limiter skips authenticated callers, the allowlist check returns
    // before the daily budget, and `fetchRequestsToday` excludes `forbidden`.
    // Uncapped, a retry loop against a typo'd host appends to a table with no
    // DELETE grant at line rate.
    const { app, egress, usage } = buildFetchEdge();
    const attempts = 40;
    for (let i = 0; i < attempts; i += 1) {
      const res = await app.inject({
        method: "GET",
        url: "/_api/fetch/https://api.evil.com/steal",
        headers: { ...HOST, origin: ORIGIN },
      });
      // Every one is still refused — the cap throttles metering, never authz.
      expect(res.statusCode).toBe(403);
    }
    const denials = usage.records.filter((r) => r.outcome === "forbidden");
    expect(denials.length).toBeGreaterThan(0);
    expect(denials.length).toBeLessThan(attempts);
    expect(egress.calls).toHaveLength(0);
    await app.close();
  });

  it("rejects a cross-origin (CSRF) caller", async () => {
    const { app, egress } = buildFetchEdge();
    const res = await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.github.com/x",
      headers: { ...HOST, origin: "https://evil.local.helix.azxlabs.io:8080" },
    });
    expect(res.statusCode).toBe(403);
    expect(egress.calls).toHaveLength(0);
    await app.close();
  });

  /**
   * CSRF on the proxy must hold for **GET**, because a proxied GET spends a
   * connection credential and returns third-party data — so the reads-are-exempt
   * shortcut `data-handler` takes is not available here. But a same-origin
   * `fetch()` GET carries no `Origin` header at all (the Fetch standard appends
   * one only for CORS-tainted requests or non-GET/HEAD methods), so an
   * Origin-only check refused every legitimate browser read through the proxy.
   * `Sec-Fetch-Site` is the signal that covers both; these pin the matrix.
   */
  describe("CSRF: Sec-Fetch-Site as the GET-capable signal", () => {
    async function call(headers: Record<string, string>) {
      const { app, egress } = buildFetchEdge();
      const res = await app.inject({
        method: "GET",
        url: "/_api/fetch/https://api.github.com/x",
        headers: { ...HOST, ...headers },
      });
      await app.close();
      return { status: res.statusCode, egressCalls: egress.calls.length };
    }

    // The regression this fixes: the real browser shape for an app's own GET.
    it("allows a same-origin GET that carries no Origin header", async () => {
      expect(await call({ "sec-fetch-site": "same-origin" })).toMatchObject({ status: 200 });
    });

    // A sibling subdomain is same-*site*, so SameSite cookies do not stop it —
    // this is precisely the threat the origin check exists for.
    it("refuses a sibling subdomain (same-site) even with no Origin", async () => {
      expect(await call({ "sec-fetch-site": "same-site" })).toEqual({
        status: 403,
        egressCalls: 0,
      });
    });

    it("refuses a cross-site caller", async () => {
      expect(await call({ "sec-fetch-site": "cross-site" })).toEqual({
        status: 403,
        egressCalls: 0,
      });
    });

    /**
     * `none` means *no initiator* — a link opened from an email client, Slack, or
     * a native app, not just the address bar. `__Host-session` is `SameSite=Lax`,
     * so the session rides that navigation; accepting `none` would let an attacker
     * spend the app's connection credential against the victim's session, outside
     * the manifest allowlist and the budget.
     */
    it("refuses `none` — no initiator is a phishing channel, not a user typing", async () => {
      expect(await call({ "sec-fetch-site": "none" })).toEqual({ status: 403, egressCalls: 0 });
    });

    /**
     * Second, independent lock on the same attack. A proxied response is returned
     * on the app's own origin with an upstream-controlled `content-type`, no CSP
     * and no `nosniff`, so a `text/html` body reached by *navigation* would execute
     * script in the app's origin. No legitimate `/_api/*` caller navigates.
     */
    it.each([
      ["sec-fetch-mode: navigate", { "sec-fetch-mode": "navigate" }],
      ["sec-fetch-dest: document", { "sec-fetch-dest": "document" }],
      ["sec-fetch-dest: iframe", { "sec-fetch-dest": "iframe" }],
      ["sec-fetch-dest: worker", { "sec-fetch-dest": "worker" }],
      ["sec-fetch-dest: sharedworker", { "sec-fetch-dest": "sharedworker" }],
      ["sec-fetch-dest: serviceworker", { "sec-fetch-dest": "serviceworker" }],
      ["service-worker header", { "service-worker": "script" }],
    ])("refuses a navigation even when same-origin (%s)", async (_label, extra) => {
      expect(await call({ "sec-fetch-site": "same-origin", ...extra })).toEqual({
        status: 403,
        egressCalls: 0,
      });
    });

    // The `accept` header is on the request safelist, so an app proxying an HTML
    // resource legitimately sends `text/html`. Unlike gate.ts's isNavigation, this
    // check must not sniff it — that would fail closed on a valid call.
    it("does not mistake an app fetching HTML for a navigation", async () => {
      expect(
        await call({ "sec-fetch-site": "same-origin", accept: "text/html,*/*" }),
      ).toMatchObject({ status: 200 });
    });

    it("allows a fetch()-shaped request with sec-fetch-dest empty", async () => {
      expect(
        await call({ "sec-fetch-site": "same-origin", "sec-fetch-dest": "empty" }),
      ).toMatchObject({ status: 200 });
    });

    // Sec-Fetch-Site is a forbidden header name, so page script cannot forge it;
    // a lying value beats the check only for a client that already holds the
    // session cookie — which is what CSRF exists to exploit *without* holding.
    it("lets Sec-Fetch-Site override a mismatched Origin", async () => {
      expect(
        await call({
          "sec-fetch-site": "same-origin",
          origin: "https://evil.local.helix.azxlabs.io:8080",
        }),
      ).toMatchObject({ status: 200 });
    });

    it("still refuses a cross-origin POST when Sec-Fetch-Site says cross-site", async () => {
      const { app, egress } = buildFetchEdge();
      const res = await app.inject({
        method: "POST",
        url: "/_api/fetch/https://api.github.com/x",
        headers: {
          ...HOST,
          "sec-fetch-site": "cross-site",
          origin: "https://evil.local.helix.azxlabs.io:8080",
        },
        payload: { a: 1 },
      });
      expect(res.statusCode).toBe(403);
      expect(egress.calls).toHaveLength(0);
      await app.close();
    });

    // Older clients that send no Fetch Metadata fall back to the exact Origin
    // match, and an absent Origin still fails closed — curl is refused.
    it("falls back to Origin when Sec-Fetch-Site is absent", async () => {
      expect(await call({ origin: ORIGIN })).toMatchObject({ status: 200 });
      expect(await call({ origin: "https://evil.local.helix.azxlabs.io:8080" })).toEqual({
        status: 403,
        egressCalls: 0,
      });
      expect(await call({})).toEqual({ status: 403, egressCalls: 0 });
    });
  });

  it("blocks when the daily request budget is exhausted", async () => {
    const { app, egress, usage } = buildFetchEdge({ requestsPerDay: 1 });
    usage.fetchToday = 1;
    const res = await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.github.com/x",
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(res.statusCode).toBe(429);
    expect(egress.calls).toHaveLength(0);
    expect(usage.records).toContainEqual(
      // statusCode mirrors the 429 the handler answers, so an operator filtering
      // the audit log for 429s to size a requestsPerDay bump actually finds them.
      expect.objectContaining({ capability: "fetch", outcome: "quota_blocked", statusCode: 429 }),
    );
    await app.close();
  });

  it("503s when the capability is not configured (no egress)", async () => {
    const { app } = buildFetchEdge({ withEgress: false });
    const res = await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.github.com/x",
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(res.statusCode).toBe(503);
    await app.close();
  });

  it("meters a proxied upstream 429 (outcome upstream_throttled) as an error", async () => {
    // Egress labels a vendor throttle `upstream_throttled` instead of `ok`, and
    // `toOutcome` folds that into the ledger's `error` — previously a throttle
    // metered as a clean `ok` and nothing keyed on outcome could find it.
    const { app, egress, usage } = buildFetchEdge();
    egress.status = 429;
    egress.outcome = "upstream_throttled";
    const res = await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.github.com/x",
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(res.statusCode).toBe(429);
    expect(usage.records).toContainEqual(
      expect.objectContaining({ capability: "fetch", outcome: "error", statusCode: 429 }),
    );
    await app.close();
  });

  const NEW_HEADERS = [
    "clear-site-data",
    "content-security-policy-report-only",
    "refresh",
    "report-to",
    "reporting-endpoints",
    "nel",
    "service-worker-allowed",
    "alt-svc",
  ] as const;

  it.each(NEW_HEADERS)("does not copy %s from egress's response onto the app's", async (name) => {
    const { app, egress } = buildFetchEdge();
    egress.responseHeaders = {
      "clear-site-data": '"cookies"',
      "content-security-policy": "default-src 'none'",
      "content-security-policy-report-only": "default-src 'none'",
      refresh: "0; url=https://evil.example/",
      "report-to": '{"group":"x","max_age":1,"endpoints":[{"url":"https://evil.example/r"}]}',
      "reporting-endpoints": 'x="https://evil.example/r"',
      nel: '{"report_to":"x","max_age":1}',
      "service-worker-allowed": "/",
      "alt-svc": 'h3="evil.example:443"',
      link: '<https://evil.example/p2>; rel="next"',
      etag: '"v1"',
      "retry-after": "30",
      "x-ratelimit-remaining": "41",
    };
    const res = await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.github.com/x",
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers[name]).toBeUndefined();
    expect(res.headers["link"]).toBe('<https://evil.example/p2>; rel="next"');
    expect(res.headers["etag"]).toBe('"v1"');
    expect(res.headers["retry-after"]).toBe("30");
    expect(res.headers["x-ratelimit-remaining"]).toBe("41");
    await app.close();
  });

  it("sets a backstop content-security-policy on every proxied response", async () => {
    const { app, egress } = buildFetchEdge();
    egress.responseHeaders = { "content-security-policy": "default-src https:" };
    const res = await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.github.com/x",
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-security-policy"]).toBe("default-src 'none'");
    await app.close();
  });

  // Body-size cap (issue #8): the edge caps both hops independently of egress.
  it("refuses an over-cap request body with 413 before forwarding (fast-path)", async () => {
    const { app, egress, usage } = buildFetchEdge({ maxBodyBytes: 64 });
    const res = await app.inject({
      method: "POST",
      url: "/_api/fetch/https://api.github.com/x",
      headers: { ...HOST, origin: ORIGIN, "content-type": "application/octet-stream" },
      payload: Buffer.alloc(65, 0x61), // 65 > 64, with a truthful content-length
    });
    expect(res.statusCode).toBe(413);
    expect(res.json().code).toBe("too_large");
    expect(egress.calls).toHaveLength(0); // never dialed egress
    expect(usage.records).not.toContainEqual(expect.objectContaining({ outcome: "ok" }));
    await app.close();
  });

  it("forwards an under-cap request body intact (no false trip)", async () => {
    const { app, egress } = buildFetchEdge({ maxBodyBytes: 64 });
    egress.drainRequest = true;
    const res = await app.inject({
      method: "POST",
      url: "/_api/fetch/https://api.github.com/x",
      headers: { ...HOST, origin: ORIGIN, "content-type": "application/octet-stream" },
      payload: Buffer.alloc(40, 0x61),
    });
    expect(res.statusCode).toBe(200);
    expect(egress.calls).toHaveLength(1);
    expect(egress.drainedBytes).toBe(40); // body transited intact
    await app.close();
  });

  it("truncates an over-cap response body streaming back to the app", async () => {
    // Over a real socket, not inject: a mid-stream destroy is a *truncation*
    // (200 + short body), not a clean error — inject can't model that.
    const { app, egress } = buildFetchEdge({ maxBodyBytes: 64 });
    // 320 bytes across chunks, no content-length ⇒ the fast-path is inert.
    egress.responseBody = Readable.from(Array.from({ length: 8 }, () => Buffer.alloc(40, 0x61)));
    await withServer(app, async (base) => {
      const res = await undiciRequest(`${base}/_api/fetch/https://api.github.com/big`, {
        method: "GET",
        headers: { ...HOST, origin: ORIGIN },
      });
      expect(res.statusCode).toBe(200);
      let got = 0;
      try {
        for await (const chunk of res.body) got += (chunk as Buffer).length;
      } catch {
        // premature close — the expected shape of a truncated response
      }
      expect(got).toBeLessThanOrEqual(64); // counter cut it at the cap
      expect(got).toBeLessThan(320); // the full body never reached the app
    });
  });

  it("forwards its own request id to egress, distinct from the instruction jti", async () => {
    // The point of the whole correlation change: the edge's log line and
    // egress's land on one value, in two different Log Analytics workspaces.
    const { app, egress } = buildFetchEdge();
    const res = await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.github.com/users/octocat",
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(res.statusCode).toBe(200);

    const call = egress.calls[0];
    expect(call?.correlationId).toBeTruthy();

    // NOT the jti. That is a single-use replay nonce burned by egress before it
    // resolves a secret (ADR-0013); ADR-0037 decision 7 says it must not be
    // refactored into a tracing concern, and a shared value would make an
    // operational id load-bearing for a security control.
    const claims = await decode(call?.instruction ?? "");
    expect(call?.correlationId).not.toBe(claims.jti);
    await app.close();
  });

  it("does not let an app shadow the correlation id with its own header", async () => {
    // `x-helix-request-id` is not on REQUEST_HEADER_SAFELIST, so it never
    // reaches `EgressRequest.headers` — and the platform headers are applied
    // after that spread besides. Two independent reasons; assert the outcome.
    const { app, egress } = buildFetchEdge();
    const forged = "00000000-0000-4000-8000-000000000000";
    const res = await app.inject({
      method: "GET",
      url: "/_api/fetch/https://api.github.com/users/octocat",
      headers: { ...HOST, origin: ORIGIN, "x-helix-request-id": forged },
    });
    expect(res.statusCode).toBe(200);

    const call = egress.calls[0];
    expect(call?.correlationId).not.toBe(forged);
    expect(call?.headers["x-helix-request-id"]).toBeUndefined();
    await app.close();
  });
});

/**
 * Everything below runs over a real socket. `app.inject()` cannot reach this
 * class of bug: light-my-request never emits `'close'` on `req.raw` when the
 * body is consumed, so a handler that mistook that for a client disconnect
 * looked perfectly healthy under inject while failing every body-bearing
 * method in production.
 */
describe("/_api/fetch over a real socket", () => {
  const URL_PATH = "/_api/fetch/https://api.github.com/x";
  const JSON_BODY = JSON.stringify({ a: 1 });
  const JSON_BODY_BYTES = Buffer.byteLength(JSON_BODY);
  const JSON_HEADERS = { ...HOST, origin: ORIGIN, "content-type": "application/json" };

  it("proxies a POST with a JSON body", async () => {
    const { app, egress, usage } = buildFetchEdge();
    egress.drainRequest = true;
    // A delay is what makes the assertion meaningful: it leaves a window in
    // which a spurious abort could land, the way a real upstream does.
    egress.delayMs = 50;
    await withServer(app, async (base) => {
      const res = await undiciRequest(`${base}${URL_PATH}`, {
        method: "POST",
        headers: JSON_HEADERS,
        body: JSON_BODY,
      });
      expect(res.statusCode).toBe(200);
      expect(await res.body.json()).toEqual({ ok: true });
    });
    expect(egress.abortedDuringCall).toBe(false); // the request finishing is not a disconnect
    expect(egress.drainedBytes).toBe(JSON_BODY_BYTES);
    expect(usage.records).toContainEqual(expect.objectContaining({ outcome: "ok" }));
  });

  it("proxies a POST with no body", async () => {
    // The reporter's `content-length: 0` control: nothing about the *content*
    // of the body matters, only that the method is one that may carry one.
    const { app, egress } = buildFetchEdge();
    egress.drainRequest = true;
    egress.delayMs = 50;
    await withServer(app, async (base) => {
      const res = await undiciRequest(`${base}${URL_PATH}`, {
        method: "POST",
        headers: { ...HOST, origin: ORIGIN },
      });
      expect(res.statusCode).toBe(200);
      await res.body.text();
    });
    expect(egress.abortedDuringCall).toBe(false);
  });

  it.each(["PUT", "PATCH", "DELETE"] as const)("proxies %s", async (method) => {
    const { app, egress } = buildFetchEdge();
    egress.drainRequest = true;
    egress.delayMs = 50;
    await withServer(app, async (base) => {
      const res = await undiciRequest(`${base}${URL_PATH}`, {
        method,
        headers: JSON_HEADERS,
        body: JSON_BODY,
      });
      expect(res.statusCode).toBe(200);
      await res.body.text();
    });
    expect(egress.abortedDuringCall).toBe(false);
  });

  it("forwards a chunked multi-chunk body intact", async () => {
    // No content-length ⇒ chunked framing, the shape the report guessed was at
    // fault. It transits fine; the verb was never the upstream's problem.
    const { app, egress } = buildFetchEdge();
    egress.drainRequest = true;
    egress.delayMs = 50;
    await withServer(app, async (base) => {
      const res = await undiciRequest(`${base}${URL_PATH}`, {
        method: "POST",
        headers: { ...HOST, origin: ORIGIN, "content-type": "application/octet-stream" },
        body: Readable.from(Array.from({ length: 4 }, () => Buffer.alloc(1_000, 0x61))),
      });
      expect(res.statusCode).toBe(200);
      await res.body.text();
    });
    expect(egress.abortedDuringCall).toBe(false);
    expect(egress.drainedBytes).toBe(4_000);
  });

  it("still proxies GET and HEAD", async () => {
    const { app, egress } = buildFetchEdge();
    egress.delayMs = 50;
    await withServer(app, async (base) => {
      for (const method of ["GET", "HEAD"] as const) {
        const res = await undiciRequest(`${base}${URL_PATH}`, {
          method,
          headers: { ...HOST, origin: ORIGIN },
        });
        expect(res.statusCode).toBe(200);
        await res.body.dump();
      }
    });
    expect(egress.calls).toHaveLength(2);
    expect(egress.abortedDuringCall).toBe(false);
  });

  it("aborts the egress call when the client hangs up mid-upload", async () => {
    // The reason the signal exists. `req.raw` is still mid-body here, so this
    // is the case a `req.aborted`-based guard would also catch.
    const { app, egress } = buildFetchEdge();
    egress.drainRequest = true;
    const stalled = new Readable({ read() {} });
    stalled.push(Buffer.alloc(16, 0x61)); // one chunk, then nothing — never ends
    await withServer(app, async (base) => {
      const ac = new AbortController();
      const pending = undiciRequest(`${base}${URL_PATH}`, {
        method: "POST",
        headers: { ...HOST, origin: ORIGIN, "content-type": "application/octet-stream" },
        body: stalled,
        signal: ac.signal,
      }).catch(() => undefined);
      await until(() => egress.calls.length === 1, "egress to be dialed");
      ac.abort();
      stalled.destroy();
      await pending;
      await until(() => egress.abortedDuringCall, "the egress call to be aborted");
    });
  });

  it("aborts the egress call when the client uploads fully and then hangs up", async () => {
    // The case that decides the primitive: the body arrived complete, so
    // `req.raw.aborted` is false and Fastify's `onRequestAbort` would never
    // fire. Watching the *response* for a premature close is what catches it.
    const { app, egress, usage } = buildFetchEdge();
    egress.drainRequest = true;
    egress.delayMs = 5_000; // held open until the client gives up
    await withServer(app, async (base) => {
      const ac = new AbortController();
      const pending = undiciRequest(`${base}${URL_PATH}`, {
        method: "POST",
        headers: JSON_HEADERS,
        body: JSON_BODY,
        signal: ac.signal,
      }).catch(() => undefined);
      await until(() => egress.drainedBytes === JSON_BODY_BYTES, "the body to arrive in full");
      ac.abort();
      await pending;
      await until(() => egress.abortedDuringCall, "the egress call to be aborted");
    });
    expect(usage.records).toContainEqual(
      expect.objectContaining({ capability: "fetch", outcome: "error" }),
    );
  });

  it("answers 413 for an over-cap request body, not 502", async () => {
    // The cap trip and a disconnect both surface as a failed egress forward in
    // the same catch, so the fix must not blur one into the other.
    const { app, egress, usage } = buildFetchEdge({ maxBodyBytes: 64 });
    egress.drainRequest = true;
    await withServer(app, async (base) => {
      const res = await undiciRequest(`${base}${URL_PATH}`, {
        method: "POST",
        headers: { ...HOST, origin: ORIGIN, "content-type": "application/octet-stream" },
        body: Readable.from(Array.from({ length: 8 }, () => Buffer.alloc(40, 0x61))),
      }).catch(() => undefined);
      expect(res?.statusCode).toBe(413);
      expect(((await res?.body.json()) as { code: string }).code).toBe("too_large");
    });
    expect(usage.records).toContainEqual(expect.objectContaining({ statusCode: 413 }));
  });
});

describe("fetch per-app concurrency cap", () => {
  it("refuses at the cap and admits again after the first finishes", async () => {
    const { app, egress, usage, leases } = buildFetchEdge({ maxAppInFlight: 1 });
    egress.delayMs = 300;
    const first = app.inject({
      method: "GET",
      url: FETCH_PATH,
      headers: { ...HOST, origin: ORIGIN },
    });
    await until(() => egress.calls.length === 1, "first egress call");
    const blocked = await app.inject({
      method: "GET",
      url: FETCH_PATH,
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(blocked.statusCode).toBe(429);
    expect(blocked.json()).toMatchObject({ code: "rate_limited" });
    expect(egress.calls).toHaveLength(1);
    expect(usage.records.filter((r) => r.outcome === "quota_blocked")).toHaveLength(0);
    await first;
    const third = await app.inject({
      method: "GET",
      url: FETCH_PATH,
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(third.statusCode).toBe(200);
    expect(leases.held(`fetch:app:${APP_ID}`)).toBe(0);
  });

  it("holds the lease for the whole streamed body", async () => {
    const { app, egress, leases } = buildFetchEdge({ maxAppInFlight: 1 });
    let phase = 0;
    egress.responseBody = new Readable({
      read() {
        if (phase === 0) {
          phase = 1;
          this.push(Buffer.from("a"));
          setTimeout(() => {
            phase = 2;
            this.push(null);
          }, 200);
        }
      },
    });
    const pending = app.inject({
      method: "GET",
      url: FETCH_PATH,
      headers: { ...HOST, origin: ORIGIN },
    });
    await until(() => leases.held(`fetch:app:${APP_ID}`) === 1, "lease held");
    await pending;
    await until(() => leases.held(`fetch:app:${APP_ID}`) === 0, "lease released");
  });

  it("releases the lease when the socket is already gone after acquire", async () => {
    const leases = new InMemoryLeaseStore();
    const baseAcquire = leases.acquire.bind(leases);
    let unblock: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      unblock = resolve;
    });
    vi.spyOn(leases, "acquire").mockImplementation(async (req, ttl) => {
      await gate;
      return baseAcquire(req, ttl);
    });
    const { app } = buildFetchEdge({ maxAppInFlight: 2, leases });
    await withServer(app, async (base) => {
      const ac = new AbortController();
      const pending = undiciRequest(`${base}${FETCH_PATH}`, {
        method: "GET",
        headers: { ...HOST, origin: ORIGIN },
        signal: ac.signal,
      }).catch(() => undefined);
      await new Promise((r) => setTimeout(r, 40));
      ac.abort();
      unblock();
      await pending;
      await until(() => leases.held(`fetch:app:${APP_ID}`) === 0, "lease released");
    });
  });

  it("releases the lease when the client hangs up mid-upload", async () => {
    const { app, egress, leases } = buildFetchEdge({ maxAppInFlight: 2 });
    egress.drainRequest = true;
    const stalled = new Readable({ read() {} });
    stalled.push(Buffer.alloc(16, 0x61));
    await withServer(app, async (base) => {
      const ac = new AbortController();
      const pending = undiciRequest(`${base}${FETCH_PATH}`, {
        method: "POST",
        headers: { ...HOST, origin: ORIGIN, "content-type": "application/octet-stream" },
        body: stalled,
        signal: ac.signal,
      }).catch(() => undefined);
      await until(() => egress.calls.length === 1, "egress dialed");
      ac.abort();
      stalled.destroy();
      await pending;
      await until(() => leases.held(`fetch:app:${APP_ID}`) === 0, "lease released");
    });
  });

  it("releases the lease when the egress call is aborted", async () => {
    const { app, egress, leases } = buildFetchEdge({ maxAppInFlight: 2 });
    egress.delayMs = 5_000;
    await withServer(app, async (base) => {
      const ac = new AbortController();
      const pending = undiciRequest(`${base}${FETCH_PATH}`, {
        method: "GET",
        headers: { ...HOST, origin: ORIGIN },
        signal: ac.signal,
      }).catch(() => undefined);
      await until(() => egress.calls.length === 1, "egress dialed");
      ac.abort();
      await pending;
      await until(() => leases.held(`fetch:app:${APP_ID}`) === 0, "lease released");
    });
  });

  it("releases the lease exactly once per completed call", async () => {
    const leases = new InMemoryLeaseStore();
    let releaseCount = 0;
    const baseRelease = leases.release.bind(leases);
    vi.spyOn(leases, "release").mockImplementation(async (id) => {
      releaseCount += 1;
      await baseRelease(id);
    });
    const { app } = buildFetchEdge({ maxAppInFlight: 5, leases });
    await app.inject({
      method: "GET",
      url: FETCH_PATH,
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(releaseCount).toBe(1);
  });

  it("does not call the lease store when the cap is off", async () => {
    class ThrowingStore extends InMemoryLeaseStore {
      override async acquire(): Promise<never> {
        throw new Error("must not acquire");
      }
    }
    const { app, egress } = buildFetchEdge({ maxAppInFlight: 0, leases: new ThrowingStore() });
    const res = await app.inject({
      method: "GET",
      url: FETCH_PATH,
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(res.statusCode).toBe(200);
    expect(egress.calls).toHaveLength(1);
  });

  it("fails closed when lease acquire throws", async () => {
    class BrokenStore extends InMemoryLeaseStore {
      override async acquire(): Promise<AcquireResult> {
        throw new Error("db down");
      }
    }
    const { app, egress } = buildFetchEdge({ maxAppInFlight: 2, leases: new BrokenStore() });
    const res = await app.inject({
      method: "GET",
      url: FETCH_PATH,
      headers: { ...HOST, origin: ORIGIN },
    });
    expect(res.statusCode).toBe(503);
    expect(res.json()).toMatchObject({
      code: "upstream_error",
      message: "fetch concurrency check unavailable",
    });
    expect(egress.calls).toHaveLength(0);
  });

  it("does not count fetch leases against LLM scopes", async () => {
    const leases = new InMemoryLeaseStore();
    const { app, egress } = buildFetchEdge({ maxAppInFlight: 1, leases });
    egress.delayMs = 300;
    void app.inject({
      method: "GET",
      url: FETCH_PATH,
      headers: { ...HOST, origin: ORIGIN },
    });
    await until(() => leases.held(`fetch:app:${APP_ID}`) === 1, "fetch lease");
    expect(leases.held(`llm:app:${APP_ID}`)).toBe(0);
  });

  it("increments admission_denied with fetch and concurrency_app on refusal", async () => {
    const recording = startRecordingTelemetry();
    try {
      const { app, egress } = buildFetchEdge({ maxAppInFlight: 1 });
      egress.delayMs = 300;
      void app.inject({
        method: "GET",
        url: FETCH_PATH,
        headers: { ...HOST, origin: ORIGIN },
      });
      await until(() => egress.calls.length === 1, "first call");
      await app.inject({
        method: "GET",
        url: FETCH_PATH,
        headers: { ...HOST, origin: ORIGIN },
      });
      const points = (await recording.metrics()).filter(
        (p) => p.name === INSTR_GATEWAY_ADMISSION_DENIED,
      );
      const denied = points.filter(
        (p) =>
          p.attributes["helix.capability"] === "fetch" &&
          p.attributes["helix.reason"] === "concurrency_app" &&
          p.attributes["helix.app_id"] === APP_ID,
      );
      expect(denied.length).toBeGreaterThanOrEqual(1);
      expect(Object.keys(denied[0]!.attributes).sort()).toEqual([
        "helix.app_id",
        "helix.capability",
        "helix.reason",
      ]);
    } finally {
      await recording.restore();
    }
  });
});
