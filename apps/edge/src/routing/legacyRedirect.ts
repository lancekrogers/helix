import type { FastifyReply, FastifyRequest } from "fastify";
import {
  ATTR_APP_ID,
  ATTR_OUTCOME,
  ROUTE_LEGACY_APP_REDIRECT,
  SPAN_LEGACY_APP_REDIRECT,
  type LegacyRedirectOutcome,
} from "@azx-pbc/shared/telemetry";
import { validateReturnPath, visibilityModeAllowed } from "../auth/validate.js";
import { publicOrigin, type EdgeConfig } from "../config.js";
import { sendNotFound } from "../errors.js";
import type { RegistryReader } from "../registry/projection.js";
import { normalizeRequestPath } from "../serving/paths.js";
import { instruments, withRootSpan } from "../telemetry.js";

export type LegacyRedirectDecision =
  | { kind: "redirected"; appId: string; target: string }
  | { kind: Exclude<LegacyRedirectOutcome, "redirected"> };

/** Pure decision: whether to 307 and where, or which failure bucket applies. */
export function decideLegacyRedirect(
  req: FastifyRequest,
  slug: string,
  deps: { config: EdgeConfig; registry: RegistryReader },
): LegacyRedirectDecision {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return { kind: "refused_path" };
  }

  const rawUrl = req.raw.url ?? "/";
  const cut = rawUrl.search(/[?#]/);
  const rawPath = cut === -1 ? rawUrl : rawUrl.slice(0, cut);
  if (rawPath.startsWith("/_") || /^\/%5[fF]/.test(rawPath)) {
    return { kind: "refused_path" };
  }

  const normalized = normalizeRequestPath(rawUrl);
  if (normalized === null) {
    return { kind: "refused_path" };
  }
  const firstSegment = normalized.slice(1).split("/")[0] ?? "";
  if (firstSegment.startsWith("_")) {
    return { kind: "refused_path" };
  }

  const validated = validateReturnPath(rawUrl);
  if (validated === null) {
    return { kind: "refused_path" };
  }

  if (!deps.registry.isLoaded()) {
    return { kind: "unknown_app" };
  }
  const entry = deps.registry.getApp(slug);
  if (!entry || entry.archived || entry.blobPrefix === null) {
    return { kind: "unknown_app" };
  }
  if (!visibilityModeAllowed(entry.visibilityMode, deps.config)) {
    return { kind: "unknown_app" };
  }

  const target = `${publicOrigin(deps.config, slug)}${validated}`;
  return { kind: "redirected", appId: entry.appId, target };
}

export function makeLegacyRedirectHook(deps: { config: EdgeConfig; registry: RegistryReader }) {
  return async function legacyRedirect(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    if (req.hostClass.kind !== "legacy-app") return;

    const slug = req.hostClass.slug;
    await withRootSpan(
      SPAN_LEGACY_APP_REDIRECT,
      { "http.route": ROUTE_LEGACY_APP_REDIRECT },
      async (span) => {
        const outcome = decideLegacyRedirect(req, slug, deps);
        instruments().legacyAppRedirects.add(1, { [ATTR_OUTCOME]: outcome.kind });
        span.setAttribute(ATTR_OUTCOME, outcome.kind);
        if (outcome.kind === "redirected") {
          span.setAttribute(ATTR_APP_ID, outcome.appId);
          reply
            .header("cache-control", "no-store")
            .header("referrer-policy", "no-referrer")
            .redirect(outcome.target, 307);
        } else {
          sendNotFound(reply);
        }
      },
      { reply },
    );
    return reply;
  };
}
