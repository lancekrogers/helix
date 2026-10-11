import { trace } from "@opentelemetry/api";
import type { FastifyReply, FastifyRequest } from "fastify";
import {
  CONSENT_ATTEMPT_TTL_SECONDS,
  ConsentStateSchema,
  CONNECT_MESSAGE_VERSION,
  ConsentAttemptTagSchema,
  ConnectOutcomeMessageSchema,
  ConsultRequestSchema,
  type ConsultResponse,
  type ConnectOutcomeMessage,
  HELIX_CONNECT_MESSAGE_SOURCE,
  ProviderRefSchema,
} from "@azx-pbc/shared";
import { spanUrlAttributes } from "@azx-pbc/shared/logging";
import {
  ATTR_APP_SLUG,
  ATTR_METHOD,
  ATTR_OUTCOME,
  ATTR_PROVIDER_REF,
  type ConsentStartOutcome,
  ROUTE_CONSENT_START,
  SPAN_CONSENT_START,
} from "@azx-pbc/shared/telemetry";
import { controlOrigin, publicOrigin, type EdgeConfig } from "../config.js";
import { sendForbidden, sendNotFound } from "../errors.js";
import { SESSION_COOKIE, parseCookieHeader } from "../auth/cookies.js";
import { hashSessionToken, type Session, type SessionStore } from "../auth/sessions.js";
import { resolveServingEntry } from "../auth/routes/appHost.js";
import { visibilityAllows } from "../auth/validate.js";
import { renderConsentTerminalPage, sendConsentPage } from "../serving/consentPages.js";
import { spanRoute } from "../telemetry.js";
import { callConsult } from "./consultCall.js";
import type { AttemptCorrelations } from "./consentCancel.js";
import type { PortalProvider } from "./portalProvider.js";
import type { RegistryEntry, RegistryReader } from "../registry/projection.js";

/**
 * `GET /_api/connections/:ref/start` — the prod entry to the consent popup.
 * A GET
 * navigation endpoint on the app host, inside the existing `/_api` reservation:
 * the session cookie is host-only here, so this is where every pre-vendor gate
 * runs and where the four terminal pages render (the portal-served pages begin
 * at the callback).
 *
 * Order of gates, and why:
 *
 * 1. **Same-origin navigation guard, fail closed.** This is a GET whose success
 *    state-change is a vendor consent attempt; it must never be reachable as a
 *    cross-site navigation riding the victim's session. The guard runs before
 *    identity on purpose — a cross-site caller learns nothing, not even whether
 *    a session exists.
 * 2. **Session check, edge-side, before any consult.** No usable session
 *    renders the sign-in-required page and never calls the portal — consent
 *    does not resume through login, so there is no redirect
 *    into the OIDC flow from here.
 * 3. **One consult call** over the internal PortalProvider seam carrying a
 *    per-call minted internal JWT: the portal decides binding
 *    effectiveness and connection status and writes the pending attempt — the
 *    edge gains no grant on any consent table.
 *
 * On `started` the popup is 302'd straight to the vendor's authorize URL — no
 * pre-consent click-through. Every other outcome is a
 * terminal page in the shared auth chrome that posts the app-facing outcome
 * message before offering Close.
 */

export interface ConsentStartRuntime {
  config: EdgeConfig;
  registry: RegistryReader;
  /** null ⇒ no auth stack on this edge; every request is sign-in required. */
  sessions: SessionStore | null;
  /** null ⇒ EDGE_PORTAL_URL unset; the consult can't run — couldn't-start. */
  portal: PortalProvider | null;
  /** null ⇒ HELIX_INTERNAL_SECRET unset; same couldn't-start answer. */
  internalKey: Buffer | null;
  /**
   * The helper's attempt-tag → OAuth-state correlation. Recorded when
   * a tagged consult starts; the cancel-acknowledgement route consumes it.
   * Optional so the existing standalone shape (tests wiring the start route
   * alone) keeps working — undefined simply records nothing.
   */
  correlations?: AttemptCorrelations | null;
}

/** The consult's JSON answer is tiny; anything bigger is not a consult response. */
/**
 * The fail-closed same-origin navigation guard: require
 * `Sec-Fetch-Site: same-origin`, fall back to Origin/Referer header
 * checks when absent, fail closed on neither.
 *
 * The three signals combine as NECESSARY, not alternative:
 *
 * - A present `Sec-Fetch-Site` must say `same-origin` — `same-site` is a
 *   sibling subdomain (the exact threat SameSite cookies don't cover), and
 *   `cross-site`/`none` are worse. Unlike the `/_api/fetch` gateway, a claimed
 *   `same-origin` is not authoritative on its own: this is a navigation
 *   endpoint, and a hand-rolled client (curl) can set any Fetch Metadata
 *   header — the adversarial matrix includes exactly that spoof
 *   against an absent Origin.
 * - Positive same-origin evidence must then come from `Origin` or `Referer`
 *   matching the app's own public origin. A real popup navigation always
 *   carries at least `Referer` under the default referrer policy, so the
 *   legitimate flow passes; a request with none of the three — or with any
 *   present-but-mismatched header — is refused. Every mismatch fails closed;
 *   nothing falls through to a more permissive signal.
 */
export function isSameOriginNavigation(
  headers: {
    "sec-fetch-site"?: string | string[] | undefined;
    origin?: string | string[] | undefined;
    referer?: string | string[] | undefined;
  },
  expectedOrigin: string,
): boolean {
  const site = headers["sec-fetch-site"];
  if (typeof site === "string" && site !== "") {
    if (site !== "same-origin") return false;
  }
  const origin = headers.origin;
  if (origin !== undefined) {
    return typeof origin === "string" && origin === expectedOrigin;
  }
  const referer = headers.referer;
  if (referer !== undefined) {
    if (typeof referer !== "string" || referer === "") return false;
    try {
      return new URL(referer).origin === expectedOrigin;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * The usable-session half of the session gate, with the consent routes' own
 * response posture (the sign-in-required page — never the gate's login
 * redirect). Same machinery: cookie parse → hash → store lookup,
 * then the per-request visibility check. Shared with the cancel-acknowledgement
 * route (`consentCancel.ts`), whose caller renders a JSON 401 on the null.
 *
 * Two deliberate narrowings:
 * - A shared-password pseudonym (`kind: "password"`) is not an identified user
 *   and can never establish a delegated connection — it gets
 *   sign-in required, same as anonymous.
 * - A session merely due for its silent refresh stays usable. The popup cannot
 *   resume through login, so bouncing a warm session to the refresh flow would
 *   strand every session older than the refresh window; identity is what
 *   consent keys on, and the group snapshot's authorization decision still
 *   runs (visibilityAllows below).
 */
export async function usableSession(
  sessions: SessionStore | null,
  req: FastifyRequest,
  entry: RegistryEntry,
): Promise<Session | null> {
  if (!sessions) return null;
  const token = parseCookieHeader(req.headers.cookie).get(SESSION_COOKIE);
  const session = token ? await sessions.lookup(hashSessionToken(token), entry.appId) : null;
  if (!session) return null;
  if (session.user.kind !== "user") return null;
  if (!visibilityAllows(entry, session.user.groups)) return null;
  return session;
}

/**
 * The optional `?attempt=<correlation tag>`.
 * `undefined` = absent (the message simply carries no tag); `null` = present
 * but invalid or repeated — refused with a 400, never silently rewritten
 * (the `rd` precedent: silence would hide probing).
 */
function attemptTagOf(req: FastifyRequest): string | null | undefined {
  const url = new URL(req.raw.url ?? "/", "http://app.invalid");
  const values = url.searchParams.getAll("attempt");
  if (values.length > 1) return null;
  const value = values[0];
  if (value === undefined) return undefined;
  return ConsentAttemptTagSchema.safeParse(value).success ? value : null;
}

/**
 * One app-facing outcome message: source,
 * version, attempt, provider, outcome, reason. Parsed through the shared
 * schema — the same definition the helper and the completion pages
 * consume — so the three producers cannot drift.
 */
function outcomeMessage(
  attempt: string | undefined,
  providerRef: string,
  outcome: ConnectOutcomeMessage["outcome"],
  reason: ConnectOutcomeMessage["reason"],
): ConnectOutcomeMessage {
  return ConnectOutcomeMessageSchema.parse({
    source: HELIX_CONNECT_MESSAGE_SOURCE,
    version: CONNECT_MESSAGE_VERSION,
    ...(attempt === undefined ? {} : { attempt }),
    provider: providerRef,
    outcome,
    reason,
  });
}

/** The couldn't-start terminal page (service failure
 * at start) — 503, posting `error`/`service_unavailable` to the opener. */
function sendCouldntStart(
  reply: FastifyReply,
  opts: {
    providerRef: string;
    attempt: string | undefined;
    appOrigin: string;
  },
): void {
  sendConsentPage(
    reply,
    503,
    renderConsentTerminalPage({
      title: "Couldn't start",
      heading: "Couldn't start",
      sub: "Couldn't start the connection — close this and select Connect again in the app.",
      message: outcomeMessage(opts.attempt, opts.providerRef, "error", "service_unavailable"),
      targetOrigin: opts.appOrigin,
    }),
  );
}

export function makeConsentStartHandler(rt: ConsentStartRuntime) {
  return spanRoute(
    SPAN_CONSENT_START,
    (req) => ({
      "http.route": ROUTE_CONSENT_START,
      [ATTR_METHOD]: req.method,
      ...spanUrlAttributes(req.url),
    }),
    async function handleConsentStart(
      req: FastifyRequest,
      reply: FastifyReply,
      slug: string,
    ): Promise<void> {
      const setOutcome = (outcome: ConsentStartOutcome): void => {
        trace.getActiveSpan()?.setAttributes({ [ATTR_OUTCOME]: outcome });
      };
      // The app's own public origin — the guard's expected value, the consult's
      // openerOrigin, and the exact
      // postMessage target of every pre-attempt terminal page on this route.
      const appOrigin = publicOrigin(rt.config, slug);

      // Gate 1 — the navigation guard, before identity.
      if (!isSameOriginNavigation(req.headers, appOrigin)) {
        setOutcome("forbidden");
        req.log.warn(
          { event: "consent.start_cross_site_refused" },
          "consent start refused: navigation is not same-origin",
        );
        sendForbidden(reply);
        return;
      }

      const entry = resolveServingEntry(rt.registry, slug, reply);
      if (!entry) {
        setOutcome("unavailable");
        return;
      }

      // The provider ref must parse before it touches a span attribute
      // (bounded, admin-chosen — like the portal's consult span) or a consult.
      const refParam = (req.params as { ref?: string }).ref ?? "";
      const ref = ProviderRefSchema.safeParse(refParam);
      if (!ref.success) {
        sendNotFound(reply); // no signal: a malformed ref is a probe, not a state
        return;
      }
      const providerRef = ref.data;
      trace.getActiveSpan()?.setAttributes({
        [ATTR_PROVIDER_REF]: providerRef,
        [ATTR_APP_SLUG]: slug,
      });

      const attempt = attemptTagOf(req);
      if (attempt === null) {
        // A malformed query, not a consent state — no outcome attribute (the
        // fetch gateway's 400 `bad_target` posture).
        sendBadRequest(reply, "Invalid attempt tag.");
        return;
      }

      // Gate 2 — session, edge-side, before the consult.
      const session = await usableSession(rt.sessions, req, entry);
      if (!session) {
        setOutcome("signin_required");
        sendConsentPage(
          reply,
          401,
          renderConsentTerminalPage({
            title: "Sign-in required",
            heading: "Sign-in required",
            sub: "Close this window, sign in to the app, then select Connect again.",
            message: outcomeMessage(attempt, providerRef, "signin_required", null),
            targetOrigin: appOrigin,
          }),
        );
        return;
      }

      // Gate 3 — the consult. An unconfigured seam is a service failure like
      // any other: couldn't-start, fail-closed, never a degraded flow.
      if (!rt.portal || !rt.internalKey) {
        setOutcome("error");
        sendCouldntStart(reply, { providerRef, attempt, appOrigin });
        return;
      }

      const consultRequest = ConsultRequestSchema.parse({
        identity: { kind: "user", userOid: session.user.oid },
        appSlug: slug,
        providerRef,
        openerOrigin: appOrigin,
        // From the edge's own auth-host origin — the single source of the
        // callback URL.
        callbackUrl: `${controlOrigin(rt.config, "auth")}/connections/callback`,
      });

      // Abort the consult if the popup goes away — watching the *response*,
      // with `writableEnded` separating completion from a hang-up (the
      // fetch-proxy and connections-proxy wiring).
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
        // No exception is recorded on the span: the fixed outcome attribute is
        // the operator signal, and the 503 below grades the span ERROR. (The
        // log line carries fixed fields only.)
        req.log.warn({ event: "consent.start_consult_failed", providerRef }, "consult call failed");
        setOutcome("error");
        sendCouldntStart(reply, { providerRef, attempt, appOrigin });
        return;
      }

      switch (consult.outcome) {
        case "started": {
          // Straight to the vendor, no pre-consent
          // click-through. The URL is the portal's assembled authorize URL;
          // the scheme check is redirect hygiene, not OAuth client code.
          const target = new URL(consult.authorizeUrl);
          if (target.protocol !== "https:") {
            setOutcome("error");
            sendCouldntStart(reply, { providerRef, attempt, appOrigin });
            return;
          }
          // The helper's cancel names its attempt by the correlation
          // tag, and the control plane's cancel arbitrates over the OAuth
          // state — the edge saw both in this one exchange, so this is where
          // the correlation is learned. State is read from the consult's own
          // URL and validated before it is ever used as a lookup key.
          const state = target.searchParams.get("state");
          if (attempt !== undefined && state !== null) {
            const parsedState = ConsentStateSchema.safeParse(state);
            if (parsedState.success) {
              rt.correlations?.remember(attempt, {
                state: parsedState.data,
                userOid: session.user.oid,
                expiresAtMs: Date.now() + CONSENT_ATTEMPT_TTL_SECONDS * 1000,
              });
            }
          }
          setOutcome("started");
          reply
            .header("cache-control", "no-store")
            .header("referrer-policy", "no-referrer")
            .redirect(target.toString(), 302);
          return;
        }
        case "already_connected":
          setOutcome("already_connected");
          sendConsentPage(
            reply,
            200,
            renderConsentTerminalPage({
              title: "Already connected",
              heading: "Already connected",
              // The designed page copy names {DisplayName}; the edge holds no
              // provider metadata and the consult's terminal outcomes carry
              // none, so the ref stands in — it is the identifier the app and
              // catalogue both use. The portal's completion pages render the
              // display name.
              sub: `You're already connected to ${providerRef}.`,
              message: outcomeMessage(attempt, providerRef, "already_connected", null),
              targetOrigin: appOrigin,
            }),
          );
          return;
        case "not_available":
          setOutcome("unavailable");
          sendConsentPage(
            reply,
            200,
            renderConsentTerminalPage({
              title: "Connection not available",
              heading: "Connection not available",
              sub: "This connection isn't available for this app right now.",
              message: outcomeMessage(attempt, providerRef, "error", "provider_unavailable"),
              targetOrigin: appOrigin,
            }),
          );
          return;
      }
    },
  );
}

/** Plain-text 400 for a malformed request an app author can fix (bad attempt
 * tag) — the terminal pages are for consent states, not malformed URLs. */
function sendBadRequest(reply: FastifyReply, message: string): void {
  reply
    .status(400)
    .header("cache-control", "no-store")
    .type("text/plain; charset=utf-8")
    .send(`${message}\n`);
}
