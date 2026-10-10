import type { FastifyReply, FastifyRequest } from "fastify";
import type { Env, PrincipalKind } from "@azx-pbc/shared";
import type { AuthConfig, EdgeConfig } from "../config.js";
import { controlOrigin, publicOrigin } from "../config.js";
import type { RegistryEntry } from "../registry/projection.js";
import { ATTR_REASON, type SessionDenialReason } from "@azx-pbc/shared/telemetry";
import { sendForbidden } from "../errors.js";
import { instruments } from "../telemetry.js";
import { SESSION_COOKIE, parseCookieHeader } from "./cookies.js";
import { hashSessionToken, type Session, type SessionStore } from "./sessions.js";
import { validateReturnPath, visibilityAllows, visibilityModeAllowed } from "./validate.js";

/**
 * The per-request session gate on app hosts (architecture §4.2): every asset
 * and `/_api/*` call happens behind it. One indexed SELECT per request — no
 * cache, so revocation is real (Appendix A.4).
 */

export interface SessionGateDeps {
  config: EdgeConfig;
  auth: AuthConfig;
  sessions: SessionStore;
}

/** Returns the session, or null after having already sent 302/401/403. */
export type SessionGate = (
  req: FastifyRequest,
  reply: FastifyReply,
  entry: RegistryEntry,
) => Promise<Session | null>;

/**
 * The metering/audit user id for an unauthenticated visitor (app-data design
 * §6). Public apps have no stable principal — there is no anonymous identity
 * in the system — so their gateway calls are attributed to this sentinel and
 * `user`-scoped storage is unavailable to them.
 */
export const ANON_USER_OID = "anon";

/**
 * The principal a `/_api/*` gateway handler (or asset request) acts for.
 * Internal/group apps always yield an authenticated caller; `public` apps yield
 * an unauthenticated one with no `user`-scope access (app-data design §6, the
 * "no anon identity" starting point).
 *
 * `env` (dev-mode design §5.4) is the partition tier the call is served in. It is
 * stamped by the resolver, not the handler: `makeCallerResolver` sets `'prod'`
 * everywhere (the production path), and only a dev surface's `DevTokenResolver`
 * (step 3) sets `'dev'`. It flows straight into `withPartition(..., env, ...)`.
 */
export type Caller =
  | {
      authenticated: true;
      oid: string;
      displayName: string;
      name: string | null;
      email: string | null;
      /** Which path minted the principal; null only for a pre-column session. */
      kind: PrincipalKind | null;
      groups: string[];
      env: Env;
    }
  | { authenticated: false; env: Env };

/**
 * How a call is attributed on the rows it writes — the gateway ledger
 * (`gateway_calls`) and collection submissions (`app_collection_items`).
 *
 * Two halves, and keeping them apart is the point (the split `App.ownerId` vs
 * `ownerName`/`ownerEmail` already draws on the control plane). `userOid` is the
 * identity: the Entra `oid` claim (ADR-0048) — compared, joined on, and used as
 * the RLS partition key, never rendered, because the platform holds no
 * Graph `/users` grant and so it resolves to nobody by policy.
 * `userName`/`userEmail` are the display half: rendered, never compared, and
 * captured at write time because `sessions` is the only id→name map there is
 * and it is swept at expiry.
 */
export interface MeterIdentity {
  userOid: string;
  userName: string | null;
  userEmail: string | null;
  /**
   * Which kind of principal this is, recorded rather than inferred. The portal
   * used to derive it from `userOid`'s shape, which is unsound: a shared-password
   * pseudonym is `pw_` + 12 base64url chars and Entra's `sub` is 32 random bytes
   * in the same alphabet — `_` included — so ~1 real subject in 262,144 begins
   * `pw_` and got rendered as an anonymous visitor. Null only while a session
   * predating the column is still alive (hours, then swept).
   */
  userKind: PrincipalKind | null;
}

/**
 * The one place a {@link Caller} becomes a metering identity.
 *
 * This exists as a function rather than an object literal at each call site
 * because there are six such sites across `llm`, `fetch` and `data-handler`, and
 * an attribution that is easy to forget at a seventh is an attribution that will
 * be missing from exactly one surface. Callers that are not a person — the `anon`
 * sentinel, a shared-password pseudonym, a dev token — carry no display half at
 * all rather than a plausible-looking stand-in: a stored `"Guest"` reads as
 * though it identified someone, whereas a null falls through to the raw
 * principal, which is the honest statement.
 */
export function meterIdentity(caller: Caller): MeterIdentity {
  return caller.authenticated
    ? {
        userOid: caller.oid,
        userName: caller.name,
        userEmail: caller.email,
        userKind: caller.kind,
      }
    : { userOid: ANON_USER_OID, userName: null, userEmail: null, userKind: "anon" };
}

/** Resolves the caller, or null after the underlying gate already responded. */
export type CallerResolver = (
  req: FastifyRequest,
  reply: FastifyReply,
  entry: RegistryEntry,
) => Promise<Caller | null>;

/**
 * Wrap the session gate with the public-app short-circuit. `public` apps are
 * served (and may call collection/shared data) without a session — the gate is
 * never invoked, so no 302/401 is emitted. Every other visibility mode goes
 * through the full gate (a `password` app yields the visitor's pseudonymous or
 * SSO session). This is the single seam the gateway keys identity off.
 */
export function makeCallerResolver(gate: SessionGate, config: EdgeConfig): CallerResolver {
  return async function resolveCaller(req, reply, entry): Promise<Caller | null> {
    // Operator policy first (EDGE_ALLOW_*_APPS): a forbidden open surface never
    // resolves a caller — the anonymous short-circuit below would otherwise
    // hand a public app's `/_api/*` calls to an anon caller.
    if (!visibilityModeAllowed(entry.visibilityMode, config)) {
      countDenial("mode_forbidden");
      sendForbidden(reply);
      return null;
    }
    if (entry.visibilityMode === "public") {
      return { authenticated: false, env: "prod" };
    }
    const session = await gate(req, reply, entry);
    if (!session) return null;
    return {
      authenticated: true,
      oid: session.user.oid,
      displayName: session.user.displayName,
      name: session.user.name,
      email: session.user.email,
      kind: session.user.kind,
      groups: session.user.groups,
      env: "prod",
    };
  };
}

/**
 * Top-level navigations get redirected into the login flow; subresource and
 * fetch requests get a 401 (redirecting a fetch breaks CORS, and the app
 * reloads into the navigation path anyway). `Sec-Fetch-Mode` is authoritative
 * where present (all evergreen browsers); the Accept sniff covers the rest.
 * Misclassification fails safe — a 401'd navigation is an error page, never
 * a leaked asset.
 */
export function isNavigation(req: FastifyRequest): boolean {
  const mode = req.headers["sec-fetch-mode"];
  if (typeof mode === "string" && mode !== "") {
    return mode === "navigate";
  }
  const accept = req.headers.accept;
  return typeof accept === "string" && accept.includes("text/html");
}

function ssoStartUrl(
  deps: SessionGateDeps,
  entry: RegistryEntry,
  rd: string,
  silent: boolean,
): URL {
  const start = new URL(`${controlOrigin(deps.config, "auth")}/start`);
  start.searchParams.set("app", entry.slug);
  start.searchParams.set("rd", rd);
  if (silent) start.searchParams.set("silent", "1");
  return start;
}

/**
 * Cold-login redirect (no session yet). `password` apps go to their own
 * same-origin challenge (passwordLogin.ts) — which itself links to SSO, since a
 * password app is "the shared password OR any SSO user"; every other mode goes
 * straight to the OIDC auth host.
 */
function redirectToLogin(
  req: FastifyRequest,
  reply: FastifyReply,
  deps: SessionGateDeps,
  entry: RegistryEntry,
): void {
  // rd is server-derived (the URL actually requested) but validated anyway;
  // anything weird collapses to the app root.
  const rd = validateReturnPath(req.raw.url ?? "/") ?? "/";
  if (entry.visibilityMode === "password") {
    const login = new URL(`${publicOrigin(deps.config, entry.slug)}/_auth/login`);
    login.searchParams.set("rd", rd);
    reply.header("cache-control", "no-store").redirect(login.toString(), 302);
    return;
  }
  reply
    .header("cache-control", "no-store")
    .redirect(ssoStartUrl(deps, entry, rd, false).toString(), 302);
}

/**
 * Silent SSO re-auth (prompt=none) for a warm session — group re-snapshot or
 * the refresh window. Only SSO sessions ever reach here: a `password` session
 * has `refreshDueAt == expiresAt` (so it expires into a cold login, not a
 * refresh) and `password` visibility never fails the per-request check. So this
 * always targets the OIDC auth host, even on a `password` app.
 */
function redirectToRefresh(
  req: FastifyRequest,
  reply: FastifyReply,
  deps: SessionGateDeps,
  entry: RegistryEntry,
): void {
  const rd = validateReturnPath(req.raw.url ?? "/") ?? "/";
  reply
    .header("cache-control", "no-store")
    .redirect(ssoStartUrl(deps, entry, rd, true).toString(), 302);
}

function sendUnauthenticated(reply: FastifyReply): void {
  reply
    .status(401)
    .header("cache-control", "no-store")
    .type("application/json; charset=utf-8")
    .send({ error: { code: "unauthorized", message: "Authentication required" } });
}

function sendRefreshRequired(reply: FastifyReply): void {
  reply
    .status(401)
    .header("cache-control", "no-store")
    .type("application/json; charset=utf-8")
    .send({ error: { code: "refresh_required", message: "Session refresh required" } });
}

/** Is this request inside the `/_api/*` platform namespace? */
function isApiPath(rawUrl: string): boolean {
  const pathname = rawUrl.split("?", 1)[0] ?? "";
  return pathname === "/_api" || pathname.startsWith("/_api/");
}

/**
 * Count a gate denial (ADR-0037 decision 8).
 *
 * The *response* is unchanged and must stay so: `errors.ts`'s senders are
 * deliberately indistinguishable, and the three denial paths here already
 * collapse to the same 401 or the same redirect on purpose, so a caller cannot
 * tell which guard fired. This records the reason where only an operator can
 * read it. `reason` is bounded by `SESSION_DENIAL_REASONS`; `appId` is not a
 * dimension here — the gate fires before authorization and per-app breakdown of
 * denials is not worth the cardinality when the interesting question is "which
 * guard, how often".
 */
function countDenial(reason: SessionDenialReason): void {
  instruments().sessionGateDenied.add(1, { [ATTR_REASON]: reason });
}

export function makeSessionGate(deps: SessionGateDeps): SessionGate {
  return async function requireSession(req, reply, entry): Promise<Session | null> {
    const token = parseCookieHeader(req.headers.cookie).get(SESSION_COOKIE);
    const session = token ? await deps.sessions.lookup(hashSessionToken(token), entry.appId) : null;

    if (!session) {
      countDenial("no_session");
      // No session (or hard-expired — lookup filters those): interactive
      // login for navigations, 401 for everything else.
      if (isNavigation(req)) {
        redirectToLogin(req, reply, deps, entry);
      } else {
        sendUnauthenticated(reply);
      }
      return null;
    }

    // Visibility is re-checked per request against the live registry entry —
    // tightening an app from internal to group bites immediately, bounded by
    // the snapshot's staleness (≤ refresh interval). The silent refresh
    // re-snapshots groups at the IdP; a user who truly lacks the group ends
    // on the callback's 403, so this cannot loop.
    if (!visibilityAllows(entry, session.user.groups)) {
      countDenial("visibility_denied");
      if (isNavigation(req)) {
        redirectToRefresh(req, reply, deps, entry);
      } else {
        sendUnauthenticated(reply);
      }
      return null;
    }

    // Refresh due: navigations take the silent-refresh detour (Appendix
    // A.5). For `/_api/*` the due time is an authorization boundary — the
    // group snapshot is stale, so fetches get a 401 the app can react to
    // (reload into the navigation path) rather than 8 more hours of service
    // on old groups. Passive assets stay lenient until hard expiry.
    if (session.refreshDueAt.getTime() <= Date.now()) {
      if (isNavigation(req)) {
        countDenial("refresh_required");
        redirectToRefresh(req, reply, deps, entry);
        return null;
      }
      if (isApiPath(req.raw.url ?? "/")) {
        countDenial("refresh_required");
        sendRefreshRequired(reply);
        return null;
      }
      // Passive assets stay lenient until hard expiry — not a denial, so not
      // counted. Counting it would make the metric say "denied" about a
      // request that was served.
    }

    return session;
  };
}
