import { randomBytes } from "node:crypto";
import { trace } from "@opentelemetry/api";
import type { FastifyReply, FastifyRequest } from "fastify";
import {
  CONSENT_NONCE_ENTRY_PATH,
  DevConsentStartResponseSchema,
  ConsultRequestSchema,
  ProviderRefSchema,
  type ApiErrorCode,
  type ConsultResponse,
} from "@azx-pbc/shared";
import { spanUrlAttributes } from "@azx-pbc/shared/logging";
import {
  ATTR_APP_SLUG,
  ATTR_METHOD,
  ATTR_OUTCOME,
  ATTR_PROVIDER_REF,
  type ConsentStartDevOutcome,
  ROUTE_CONSENT_START_DEV,
  SPAN_CONSENT_START_DEV,
} from "@azx-pbc/shared/telemetry";
import { controlOrigin, type GatewayConfig } from "../config.js";
import { sendNotFound } from "../errors.js";
import type { CallerResolver } from "../auth/gate.js";
import { resolveServingEntry } from "../auth/routes/appHost.js";
import { callConsult } from "../routing/consultCall.js";
import type { PortalProvider } from "../routing/portalProvider.js";
import { spanRoute } from "../telemetry.js";
import type { RegistryReader } from "../registry/projection.js";

/**
 * `POST /:slug/_api/connections/:ref/start` — the dev tier's consent entry.
 * A dev app's
 * page POSTs with its bearer dev token and receives a **single-use popup
 * URL**; the popup is the one-time handoff that gets consent started without
 * the token ever appearing in a URL (a popup navigation
 * can neither carry the Authorization header nor ride this Origin contract).
 *
 * The prod start route's factories are reused, seams swapped, exactly like
 * every other dev-gateway capability:
 * the caller identity comes from the same `CallerResolver` seam (the dev
 * token resolver — its Origin allowlist check IS this route's navigation
 * guard), the consult rides the same `callConsult` seam as the prod route,
 * and the wire contract is the shared `DevConsentStartResponseSchema`. What
 * differs is the response shape, and only that: a JSON popup URL instead of a
 * 302 — the popup URL carries ONLY the attempt's single-use nonce, and the
 * vendor authorize URL the consult returned is deliberately dropped (the
 * nonce entry re-derives it portal-side at redemption; the verifier never
 * leaves the attempt row).
 */

export interface DevConsentStartRuntime {
  config: GatewayConfig;
  registry: RegistryReader;
  /** The dev-token resolver (bearer + Origin allowlist) — the swapped seam. */
  resolveCaller: CallerResolver;
  /** null ⇒ EDGE_PORTAL_URL unset; the consult can't run — fail-closed 503. */
  portal: PortalProvider | null;
  /** null ⇒ HELIX_INTERNAL_SECRET unset; the same fail-closed answer. */
  internalKey: Buffer | null;
}

/** The consult request's identity nonce: 256 bits, base64url — the same
 * entropy discipline as the consult's own `state` (ConsentStateSchema). */
const FRESH_BYTES = 32;

/** Plain JSON API errors, the dev resolver's own response shape. */
function sendApiError(
  reply: FastifyReply,
  status: number,
  code: ApiErrorCode,
  message: string,
): void {
  reply
    .status(status)
    .header("cache-control", "no-store")
    .type("application/json; charset=utf-8")
    .send({ error: { code, message } });
}

export function makeDevConsentStartHandler(rt: DevConsentStartRuntime) {
  return spanRoute(
    SPAN_CONSENT_START_DEV,
    (req) => ({
      "http.route": ROUTE_CONSENT_START_DEV,
      [ATTR_METHOD]: req.method,
      ...spanUrlAttributes(req.url),
    }),
    async function handleDevConsentStart(
      req: FastifyRequest,
      reply: FastifyReply,
      slug: string,
    ): Promise<void> {
      const setOutcome = (outcome: ConsentStartDevOutcome): void => {
        trace.getActiveSpan()?.setAttributes({ [ATTR_OUTCOME]: outcome });
      };

      const entry = resolveServingEntry(rt.registry, slug, reply);
      if (!entry) {
        setOutcome("unavailable");
        return;
      }

      // The provider ref must parse before it touches a span attribute or a
      // consult (the prod start route's posture: a malformed ref is a probe,
      // not a state).
      const refParam = (req.params as { ref?: string }).ref ?? "";
      const ref = ProviderRefSchema.safeParse(refParam);
      if (!ref.success) {
        sendNotFound(reply);
        return;
      }
      const providerRef = ref.data;
      trace.getActiveSpan()?.setAttributes({
        [ATTR_PROVIDER_REF]: providerRef,
        [ATTR_APP_SLUG]: slug,
      });

      // Gate — the dev resolver, BEFORE any consult: bearer token validity,
      // app binding, lifetime, and the Origin allowlist (the dev resolver's
      // Origin contract — an invalid or unregistered Origin is refused here
      // and reaches the consult for nothing).
      const caller = await rt.resolveCaller(req, reply, entry);
      if (!caller) {
        setOutcome("forbidden");
        return;
      }
      if (!caller.authenticated) {
        // The union's unauthenticated arm belongs to the session gate; the
        // dev resolver never returns it, but the response must never hang.
        setOutcome("forbidden");
        sendApiError(reply, 403, "forbidden", "dev token is not valid for this app");
        return;
      }
      // The validated Origin is exactly what the resolver admitted — it is
      // the value the attempt records as the opener origin (the completion
      // message's target). A resolver that admitted
      // a caller without setting it would be a skew; fail closed.
      const openerOrigin = req.devCorsOrigin;
      if (!openerOrigin) {
        setOutcome("forbidden");
        sendApiError(reply, 403, "forbidden", "origin is not registered for this dev token");
        return;
      }

      // An unconfigured seam is a service failure like any other: fail-closed
      // 503, never a degraded flow.
      if (!rt.portal || !rt.internalKey) {
        setOutcome("error");
        sendApiError(
          reply,
          503,
          "capability_unavailable",
          "connections capability is not configured",
        );
        return;
      }

      const nonce = randomBytes(FRESH_BYTES).toString("base64url");
      // env is pinned by the identity kind — nothing on the request can
      // parameterize it (the resolver bakes env='dev'; the consult's contract
      // carries no env field).
      const consultRequest = ConsultRequestSchema.parse({
        identity: { kind: "dev", developerOid: caller.oid, nonce },
        appSlug: slug,
        providerRef,
        openerOrigin,
        // From the edge's own auth-host origin — the single source of the
        // callback URL.
        callbackUrl: `${controlOrigin(rt.config, "auth")}/connections/callback`,
      });

      // Abort the consult if the caller goes away — the shared seam wiring.
      const abort = new AbortController();
      reply.raw.on("close", () => {
        if (!reply.raw.writableEnded) abort.abort();
      });

      let consult: ConsultResponse;
      try {
        consult = await callConsult(
          rt.portal,
          rt.internalKey,
          consultRequest,
          String(req.id),
          abort.signal,
        );
      } catch {
        // Fixed-string log fields only — no consult body, no token material.
        req.log.warn(
          { event: "consent.dev_start_consult_failed", providerRef },
          "consult call failed",
        );
        setOutcome("error");
        sendApiError(
          reply,
          503,
          "capability_unavailable",
          "couldn't start the connection; try again shortly",
        );
        return;
      }

      switch (consult.outcome) {
        case "started": {
          // The handoff: auth host + the entry path + the nonce, nothing else.
          // The consult's authorizeUrl is dropped here by
          // design — carrying it would bypass the single-use redemption that
          // makes the popup one-time; the portal re-derives it at redemption
          // from the attempt it stored (state + verifier stay server-side).
          const popupUrl = new URL(CONSENT_NONCE_ENTRY_PATH, controlOrigin(rt.config, "auth"));
          popupUrl.searchParams.set("nonce", nonce);
          setOutcome("started");
          reply
            .header("cache-control", "no-store")
            .type("application/json; charset=utf-8")
            .send(
              DevConsentStartResponseSchema.parse({
                outcome: "started",
                popupUrl: popupUrl.toString(),
              }),
            );
          return;
        }
        case "already_connected": {
          setOutcome("already_connected");
          reply
            .header("cache-control", "no-store")
            .type("application/json; charset=utf-8")
            .send(DevConsentStartResponseSchema.parse({ outcome: "already_connected" }));
          return;
        }
        case "not_available": {
          setOutcome("unavailable");
          reply
            .header("cache-control", "no-store")
            .type("application/json; charset=utf-8")
            .send(DevConsentStartResponseSchema.parse({ outcome: "not_available" }));
          return;
        }
      }
    },
  );
}
