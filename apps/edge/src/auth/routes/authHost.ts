import type { FastifyReply, FastifyRequest } from "fastify";
import type { AuthConfig, EdgeConfig } from "../../config.js";
import { controlOrigin, publicOrigin } from "../../config.js";
import type { RegistryReader } from "../../registry/projection.js";
import { sendAuthFlowError, sendNotFound, sendUnavailable } from "../../errors.js";
import {
  FLOW_COOKIE,
  clearFlowCookie,
  parseCookieHeader,
  serializeFlowCookie,
} from "../cookies.js";
import type { AuthKeys } from "../secrets.js";
import { FLOW_TTL_SEC, mintFlowToken, verifyFlowToken, type FlowState } from "../flow.js";
import { mintHandoffToken } from "../handoff.js";
import {
  codeChallengeFor,
  newCodeVerifier,
  newOidcNonce,
  newOidcState,
  type OidcClient,
} from "../oidc.js";
import { newSessionId, type SessionStore } from "../sessions.js";
import { resolveAppForAuth, validateReturnPath, visibilityAllows } from "../validate.js";
import { spanUrlAttributes } from "@azx-pbc/shared/logging";
import {
  ROUTE_AUTH_CALLBACK,
  ROUTE_AUTH_START,
  SPAN_AUTH_CALLBACK,
  SPAN_AUTH_START,
} from "@azx-pbc/shared/telemetry";
import { spanRoute } from "../../telemetry.js";

/**
 * The auth host (architecture Appendix A.1 steps 2–7): `/start` begins a
 * login (or a prompt=none silent refresh) and `/callback` finishes it — code
 * exchange, visibility check, pending session row, handoff mint. This file
 * plus handoff.ts/flow.ts/validate.ts is the dedicated-review surface; keep
 * unrelated churn out of it.
 */

export interface AuthHostRuntime {
  config: EdgeConfig;
  auth: AuthConfig;
  keys: AuthKeys;
  registry: RegistryReader;
  sessions: SessionStore;
  oidc: OidcClient;
}

function requestUrl(req: FastifyRequest): URL {
  // The placeholder base is never used in comparisons — only path + query are.
  return new URL(req.raw.url ?? "/", "http://auth.invalid");
}

/** Respond for the app-resolution failure kinds shared by both routes. */
function sendAppResolutionFailure(
  reply: FastifyReply,
  kind: "unknown" | "registry-unavailable" | "unsupported-mode",
): void {
  if (kind === "registry-unavailable") {
    sendUnavailable(reply, "Registry unavailable; try again shortly.");
  } else if (kind === "unsupported-mode") {
    sendUnavailable(reply, "This app's visibility mode is not supported yet.");
  } else {
    sendNotFound(reply);
  }
}

export function makeStartHandler(rt: AuthHostRuntime) {
  return spanRoute(
    SPAN_AUTH_START,
    (req) => ({ "http.route": ROUTE_AUTH_START, ...spanUrlAttributes(req.url) }),
    async function handleStart(req: FastifyRequest, reply: FastifyReply): Promise<void> {
      const url = requestUrl(req);
      const slug = url.searchParams.get("app") ?? undefined;
      const resolved = resolveAppForAuth(rt.registry, slug);
      if (resolved.kind !== "ok") {
        sendAppResolutionFailure(reply, resolved.kind);
        return;
      }

      // Open-redirect defense (Appendix A.1 step 2): a bad rd is a hard error,
      // never silently rewritten — silence would hide live attack attempts.
      const rd = validateReturnPath(url.searchParams.get("rd") ?? undefined);
      if (rd === null) {
        sendAuthFlowError(reply, 400, "Invalid return path.");
        return;
      }

      if (!rt.oidc.isReady()) {
        sendUnavailable(reply, "Sign-in temporarily unavailable; try again shortly.");
        return;
      }

      const flow: FlowState = {
        state: newOidcState(),
        nonce: newOidcNonce(),
        codeVerifier: newCodeVerifier(),
        app: resolved.entry.slug,
        rd,
        silent: url.searchParams.get("silent") === "1",
      };
      const authorizeUrl = rt.oidc.authorizationUrl({
        state: flow.state,
        nonce: flow.nonce,
        codeChallenge: await codeChallengeFor(flow.codeVerifier),
        ...(flow.silent ? { prompt: "none" as const } : {}),
      });

      reply
        .header(
          "set-cookie",
          serializeFlowCookie(await mintFlowToken(flow, rt.keys.flowKey), FLOW_TTL_SEC),
        )
        .header("cache-control", "no-store")
        // The URL we're ON carries app + rd; keep it out of Referer headers on
        // the IdP round-trip (modern defaults already strip the path, but be
        // explicit — same posture as /complete).
        .header("referrer-policy", "no-referrer")
        .redirect(authorizeUrl, 302);
    },
  );
}

export function makeCallbackHandler(rt: AuthHostRuntime) {
  return spanRoute(
    SPAN_AUTH_CALLBACK,
    // The OIDC `code` is in this URL. `spanUrlAttributes` drops the whole query,
    // so `url.path` is the bare route and nothing else (ADR-0037 decision 6).
    (req) => ({ "http.route": ROUTE_AUTH_CALLBACK, ...spanUrlAttributes(req.url) }),
    async function handleCallback(req: FastifyRequest, reply: FastifyReply): Promise<void> {
      // Every terminal response burns the flow cookie — it is strictly one-shot.
      reply.header("set-cookie", clearFlowCookie()).header("cache-control", "no-store");

      const flowToken = parseCookieHeader(req.headers.cookie).get(FLOW_COOKIE);
      const flow = flowToken ? await verifyFlowToken(flowToken, rt.keys.flowKey) : null;
      if (!flow) {
        sendAuthFlowError(reply, 400, "Sign-in state is missing or expired.");
        return;
      }

      // Re-resolve: the app may have been archived/retuned mid-roundtrip.
      const resolved = resolveAppForAuth(rt.registry, flow.app);
      if (resolved.kind !== "ok") {
        sendAppResolutionFailure(reply, resolved.kind);
        return;
      }
      const entry = resolved.entry;

      // openid-client needs the exact public callback URL (redirect_uri match).
      const callbackUrl = new URL(
        (req.raw.url ?? "/callback").replace(/^[^?]*/, "/callback"),
        controlOrigin(rt.config, "auth"),
      );
      const outcome = await rt.oidc.exchangeCode(callbackUrl, {
        state: flow.state,
        nonce: flow.nonce,
        codeVerifier: flow.codeVerifier,
      });

      if (outcome.kind === "interaction-required" && flow.silent) {
        // Silent refresh needs a human: rerun interactively, same destination.
        const restart = new URL(`${controlOrigin(rt.config, "auth")}/start`);
        restart.searchParams.set("app", entry.slug);
        restart.searchParams.set("rd", flow.rd);
        reply.header("referrer-policy", "no-referrer").redirect(restart.toString(), 302);
        return;
      }
      if (outcome.kind !== "ok") {
        sendAuthFlowError(reply, 400, "Sign-in could not be completed.");
        return;
      }

      // Authorization (Appendix A.5): authenticated ≠ allowed to see this app.
      if (!visibilityAllows(entry, outcome.identity.groups)) {
        sendAuthFlowError(reply, 403, "Your account does not have access to this app.");
        return;
      }

      // Pending session row first, then the handoff that references it — the
      // token is worthless unless this exact row redeems (sessions.ts).
      const sessionId = newSessionId();
      const now = Date.now();
      await rt.sessions.createPending({
        id: sessionId,
        appId: entry.appId,
        user: {
          oid: outcome.identity.oid,
          displayName: outcome.identity.displayName,
          name: outcome.identity.name,
          email: outcome.identity.email,
          kind: "user",
          groups: outcome.identity.groups,
        },
        refreshDueAt: new Date(now + rt.auth.refreshAfterMs),
        expiresAt: new Date(now + rt.auth.sessionTtlMs),
      });
      const handoff = await mintHandoffToken(
        { sessionId, appId: entry.appId, rd: flow.rd },
        rt.keys.handoffKey,
        rt.auth.handoffTtlSec,
      );

      const complete = new URL(`${publicOrigin(rt.config, entry.slug)}/_auth/complete`);
      complete.searchParams.set("token", handoff);
      reply
        // The token is in this URL: keep it out of referrers and caches. A 302
        // isn't cacheable without explicit headers, but the Location carries a
        // live credential — say so rather than rely on the default (issue #20;
        // the access-log half is `src/logging.ts`).
        .header("referrer-policy", "no-referrer")
        .header("cache-control", "no-store")
        .redirect(complete.toString(), 302);
    },
  );
}
