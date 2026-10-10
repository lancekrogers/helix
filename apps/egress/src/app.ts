import Fastify, { type FastifyServerOptions, type FastifyInstance } from "fastify";
import { HealthStatusSchema, OUTCOME_HEADER } from "@azx-pbc/shared";
import { traceContextMixin } from "@azx-pbc/telemetry/correlation";
import { loggerOption, requestIdOptions } from "@azx-pbc/shared/logging";
import type { EgressConfig } from "./config.js";
import type { SecretResolver } from "./secrets.js";
import type { InstructionBurnStore } from "./burn.js";
import type { DelegatedWiring } from "./delegated.js";
import { DelegatedResolver } from "./delegated.js";
import { ConnectionRenewer } from "./renewal.js";
import { makeExchangeHandler, type ExchangeDeps } from "./exchange.js";
import { makeProxyHandler } from "./proxy.js";
import { ROUTE_EGRESS_EXCHANGE } from "@azx-pbc/shared/telemetry";
import { SERVICE_NAME } from "./serviceName.js";

/**
 * helix-egress — the mechanism plane (architecture §3). Internal-only: it answers
 * the edge's `/proxy` calls, never app users. It is the one component that holds
 * plaintext secrets and a route to the public internet; everything else about it
 * is deliberately tiny.
 */

// Re-exported so `server.ts` keeps its single `./app.js` import. The constant
// itself lives in its own module to keep `telemetry.ts` out of this one's
// import graph (ADR-0037 decision 3).
export { SERVICE_NAME };

export interface EgressDeps {
  config: EgressConfig;
  /** null ⇒ no secret store; keyless proxying works, secret-backed calls 502. */
  resolver: SecretResolver | null;
  /** HKDF-derived instruction-verify key (shared derivation with the edge). */
  instructionKey: Buffer;
  /** One-time `jti` burn (issue #3). null ⇒ replay protection off (tests only). */
  burnStore: InstructionBurnStore | null;
  /**
   * The code-exchange operation. null (the default, so existing
   * constructions and tests without it keep working) unwires the operation:
   * the route stays registered and refuses every caller fail-closed (the zero
   * verify key verifies nothing legitimate → 401, disclosing nothing). A
   * wired operation with no custody still answers a verified caller 503.
   */
  exchange?: ExchangeDeps | null;
  /**
   * The delegated-call resolution: the caller's-connection
   * resolver + renewer ingredients behind the proxy's `provider` branch.
   * null/omitted (existing constructions) unwires it: a delegated instruction
   * is refused fail-closed (502, the mechanism not wired), and every other
   * call is byte-identical to before.
   */
  delegated?: DelegatedWiring | null;
}

/**
 * The unwired operation: a zero verify key — which verifies nothing legitimate,
 * so the unwired route answers 401 to every caller (fail closed, disclosing
 * nothing) — and no custody/cache. Real deployments always build real exchange
 * deps in `server.ts` (the exchange secret is required at boot); this shape
 * exists for constructions without the field (existing tests).
 */
const UNWIRED_EXCHANGE: ExchangeDeps = {
  exchangeKey: Buffer.alloc(32),
  providers: null,
  credentialStore: null,
  delegatedStore: null,
  allowPrivate: false,
  allowInsecureConnection: false,
  timeoutMs: 30_000,
};

export function buildApp(
  deps: EgressDeps,
  /** Test seam: replace the pino logger wholesale (a capture stream for the
   * log-scan suites). Production always uses the redacting `loggerOption`. */
  loggerOverride?: FastifyServerOptions["logger"],
): FastifyInstance {
  // The same redacting serializer the edge and portal use (issue #20). Nothing
  // here is query-borne today — `POST /proxy` carries the attested instruction
  // in a header and the target in another — so this is for the next route, not
  // a live leak.
  const app = Fastify({
    logger:
      loggerOverride ?? loggerOption(undefined, { prefix: "EGRESS", mixin: traceContextMixin }),
    // The ONE service that adopts its caller's request id. Its only caller is
    // the edge, over a hop whose authority comes from the signed instruction
    // (ADR-0013) — and adopting it is what joins the two halves of a
    // fetch-proxy call, which today land in two different Log Analytics
    // workspaces with nothing in common. The id is still shape-validated:
    // egress has `external: true` ingress, so a forged header must not be
    // able to put a newline or 8KB into a retained log field.
    ...requestIdOptions({ trustInbound: true }),
  });

  // The proxy re-streams arbitrary request bodies; never buffer/parse them.
  // `removeAllContentTypeParsers` is essential: Fastify's BUILT-IN
  // `application/json`/`text/plain` parsers would otherwise consume `req.raw`
  // before the handler forwards it (the catch-all `*` only covers types without
  // a parser). The LLM call is always `application/json`, so without this the
  // body reaches the upstream empty. After removing them, the passthrough leaves
  // `req.raw` readable for undici for every content type.
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("*", (_req, payload, done) => done(null, payload));

  // Fastify's default error handler puts `error.message` in the response body,
  // and the edge forwards an egress body to the untrusted app verbatim
  // (`apps/edge/src/gateway/fetch.ts`). In the one process that holds plaintext
  // secrets that is a leak channel, not just noise: V8 embeds a ~10-character
  // prefix of its input in a `JSON.parse` message, so a throw anywhere near
  // credential material would hand the app a fragment of a live key. Answer with
  // a fixed opaque body and keep the detail on the log, where it belongs. Every
  // deliberate refusal already returns through the proxy's own `fail()`, so
  // reaching here at all means an unhandled throw.
  app.setErrorHandler((err, req, reply) => {
    req.log.error({ err, event: "egress.unhandled_error" }, "unhandled error in egress");
    reply.header(OUTCOME_HEADER, "error");
    reply.code(500).send({ code: "upstream_error", message: "egress request failed" });
  });

  app.route({
    method: ["GET", "HEAD"],
    url: "/health",
    handler: async () =>
      HealthStatusSchema.parse({
        status: "ok",
        service: SERVICE_NAME,
        uptime: process.uptime(),
      }),
  });

  const proxy = makeProxyHandler({
    instructionKey: deps.instructionKey,
    resolver: deps.resolver,
    burnStore: deps.burnStore,
    limits: deps.config.limits,
    allowPrivate: deps.config.allowPrivate,
    allowInsecureConnection: deps.config.allowInsecureConnection,
    // The delegated resolution, built against the proxy's own dispatcher so
    // the renewer's vendor round-trips ride the same pinned transport as the
    // exchange's (the one transport seam).
    delegated: deps.delegated
      ? (dispatcher) =>
          new DelegatedResolver({
            pool: deps.delegated!.pool,
            providers: deps.delegated!.providers,
            delegatedStore: deps.delegated!.delegatedStore,
            renewer: new ConnectionRenewer({
              pool: deps.delegated!.pool,
              providers: deps.delegated!.providers,
              credentialStore: deps.delegated!.credentialStore,
              delegatedStore: deps.delegated!.delegatedStore,
              dispatcher,
              timeoutMs: deps.delegated!.timeoutMs,
              allowInsecureConnection: deps.delegated!.allowInsecureConnection,
              lockAcquireTimeoutMs: deps.delegated!.lockAcquireTimeoutMs,
            }),
          })
      : undefined,
  });
  // The proxy holds one shared, long-lived dispatcher (connection pooling +
  // per-connection SSRF pin); drain its pooled sockets on teardown so tests and
  // graceful shutdown don't leak keep-alive handles.
  app.addHook("onClose", async () => {
    await proxy.dispatcher.close();
    await proxy.llmDispatcher.close();
  });

  app.route({
    method: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    url: "/proxy",
    handler: proxy.handler,
  });

  // The code-exchange operation: a NEW internal route, not a
  // bend of /proxy — the instruction contract binds origin/method/path per app
  // call and an exchange has no app-side counterpart.
  // It rides the proxy's SAME pinned dispatcher, so the SSRF controls and the
  // trace boundary are process-wide facts, not per-route choices. Unwired, the
  // route refuses every caller fail-closed (see UNWIRED_EXCHANGE).
  const exchange = deps.exchange ?? UNWIRED_EXCHANGE;
  app.route({
    method: "POST",
    url: ROUTE_EGRESS_EXCHANGE,
    handler: makeExchangeHandler({ ...exchange, dispatcher: proxy.dispatcher }),
  });

  return app;
}
