import type { FastifyRequest } from "fastify";
import { SLUG_PATTERN } from "@azx-pbc/shared";
import { publicOrigin, type EdgeConfig } from "../config.js";
import type { RegistryEntry, RegistryReader } from "../registry/projection.js";

/**
 * Parameter validation for the auth host (architecture Appendix A.1 step 2):
 * `rd` validation is what stops `/start` being an open redirector, and the
 * `app` lookup is what stops handoffs being minted for hosts we don't serve.
 */

const MAX_RD_LENGTH = 2000;
// eslint-disable-next-line no-control-regex
const CONTROL_OR_SPACE = /[\x00-\x20\x7f]/;

/**
 * A return path is acceptable only if it is a same-origin absolute path:
 * starts with exactly one `/`, no scheme, no authority, no control chars,
 * and survives URL resolution without changing origin. Null = reject.
 *
 * `/_api/*` is additionally refused. A login redirect target should never be an
 * API endpoint, and this one is load-bearing: the session gate sets
 * `rd = validateReturnPath(req.raw.url)` on any unauthenticated request, so
 * without this an attacker could hand a *signed-out* victim a link to
 * `/_api/fetch/<url>` and have the SSO flow itself walk them through login and
 * land them on the proxy as a top-level navigation. The navigation is refused at
 * the gateway too (see `makeSameOriginCheck`); this closes the door that
 * manufactures it.
 */
export function validateReturnPath(rd: string | undefined): string | null {
  if (rd === undefined || rd === "") return "/";
  if (rd.length > MAX_RD_LENGTH) return null;
  if (CONTROL_OR_SPACE.test(rd)) return null;
  // `//host`, `/\host` and `\…` are network-path / IE-style absolute URLs.
  if (!rd.startsWith("/") || rd.startsWith("//") || rd.startsWith("/\\")) return null;

  // Round-trip: resolved against a known origin, it must stay on that origin
  // and remain path-only (catches encodings the prefix checks miss).
  let resolved: URL;
  try {
    resolved = new URL(rd, "https://rd-probe.invalid");
  } catch {
    return null;
  }
  if (resolved.origin !== "https://rd-probe.invalid") return null;
  // Checked post-resolution so `/x/../_api/y` and encoded separators can't slip by.
  const path = resolved.pathname.toLowerCase();
  if (path === "/_api" || path.startsWith("/_api/")) return null;
  return rd;
}

export type AppForAuth =
  | { kind: "ok"; entry: RegistryEntry }
  | { kind: "unknown" }
  | { kind: "registry-unavailable" }
  /** `public` visibility — no session is ever minted, so SSO has nothing to do. */
  | { kind: "unsupported-mode" };

/** Resolve and vet the `app` parameter / host slug for the login flow. */
export function resolveAppForAuth(registry: RegistryReader, slug: string | undefined): AppForAuth {
  if (!registry.isLoaded()) return { kind: "registry-unavailable" };
  if (!slug || !SLUG_PATTERN.test(slug)) return { kind: "unknown" };
  const entry = registry.getApp(slug);
  // Archived apps answer like unknown ones here — no session minting, and no
  // distinguishing the two through the auth host.
  if (!entry || entry.archived) return { kind: "unknown" };
  // SSO serves internal, group, AND password apps: a `password` app is "the
  // shared password OR any SSO user" (the password login UI links here). Only
  // `public` has no session at all, so it can't use the OIDC flow.
  if (entry.visibilityMode === "public") {
    return { kind: "unsupported-mode" };
  }
  return { kind: "ok", entry };
}

/**
 * Cross-app CSRF guard for state-changing requests on app hosts (architecture
 * §4.2): the `Origin` header must exactly match the app's own public origin.
 * `SameSite` does not protect one app's `/_api/*` from a sibling subdomain's
 * form/fetch POST riding the user's session, so the gateway and logout require
 * a matching Origin. A missing Origin fails closed.
 */
export function isSameOrigin(
  originHeader: string | string[] | undefined,
  config: EdgeConfig,
  slug: string,
): boolean {
  return typeof originHeader === "string" && originHeader === publicOrigin(config, slug);
}

/**
 * `Sec-Fetch-Site`, where the browser sent one, as a same-origin verdict.
 * Returns `undefined` when the header is absent so the caller can fall back.
 *
 * Fetch Metadata is the right signal for a CSRF guard that must also cover
 * **GET**: it rides every request from every current browser, whereas `Origin`
 * is appended only for CORS-tainted requests or non-GET/HEAD methods. It is also
 * a forbidden header name, so page script cannot set or spoof it, and it
 * distinguishes `same-site` (a sibling subdomain — the exact threat the Origin
 * check exists for, and the one `SameSite` cookies do not cover) from
 * `same-origin`.
 *
 * **`none` is NOT accepted here**, unlike {@link isSameOriginFormPost}. `none`
 * does not mean "the user typed it" — it means *no initiator*, which a link
 * opened from an email client, Slack, or a native app also produces. That is a
 * first-class phishing channel, and `__Host-session` is `SameSite=Lax`, so the
 * session rides a top-level GET navigation: accepting `none` would let an
 * attacker spend an app's connection credential against the victim's session,
 * outside the manifest allowlist and the per-app budget.
 *
 * The form-post symmetry does not carry. That guards a top-level form
 * navigation, where `none` is a shape the legitimate flow produces. `/_api/*`
 * has no navigation flow at all — page script always sends `same-origin`.
 */
function fetchMetadataSameOrigin(secFetchSite: string | string[] | undefined): boolean | undefined {
  if (typeof secFetchSite !== "string" || secFetchSite === "") return undefined;
  return secFetchSite === "same-origin";
}

/**
 * Whether the browser told us this is a top-level navigation or a document-ish
 * load. No legitimate `/_api/*` caller is one: the fetch shim patches only
 * `fetch`/`XHR`, every example app uses `fetch()`, and the deploy skill states
 * outright that forms, `<img>` and `EventSource` do not go through the proxy.
 *
 * Refusing them matters because a proxied response is returned on the app's own
 * origin with an upstream-controlled `content-type`, no CSP and no `nosniff` —
 * so a `text/html` upstream body reached by *navigation* executes script in the
 * app's origin with the session in scope. Blocking the navigation closes that
 * without having to rewrite every proxied response.
 *
 * Only explicit browser signals count here. `gate.ts`'s `isNavigation`
 * deliberately falls back to sniffing `Accept: text/html`, which is right there
 * (a misclassified navigation is an error page) and wrong here: `accept` is on
 * the request safelist, so an app legitimately proxying an HTML resource sends
 * exactly that, and misclassifying it would fail *closed* on a valid call. A
 * browser old enough to omit Fetch Metadata omits `Sec-Fetch-Site` too, so its
 * navigations are already refused by the `Origin` fallback.
 */
function isDocumentRequest(req: FastifyRequest): boolean {
  const dest = req.headers["sec-fetch-dest"];
  return (
    req.headers["sec-fetch-mode"] === "navigate" ||
    dest === "document" ||
    dest === "iframe" ||
    dest === "embed" ||
    dest === "object"
  );
}

/** Service-worker registration and worker-destination loads on same-origin URLs. */
function isWorkerRegistrationRequest(req: FastifyRequest): boolean {
  if (req.headers["service-worker"] !== undefined) return true;
  const dest = req.headers["sec-fetch-dest"];
  return dest === "worker" || dest === "sharedworker" || dest === "serviceworker";
}

/**
 * The gateway's CSRF seam (dev-mode §5.4). The `/_api/*` handlers call this to
 * decide whether a request's Origin is allowed. On the edge it is the
 * same-origin check below; the dev-gateway swaps in an allowlist check (the
 * `DevTokenResolver` has already matched the Origin against the token's
 * registered origins, so its `checkOrigin` returns true). Injected into the
 * handler runtimes alongside `resolveCaller`.
 */
export type OriginCheck = (req: FastifyRequest, entry: RegistryEntry) => boolean;

/**
 * The production origin check for `/_api/*`.
 *
 * `Sec-Fetch-Site` is authoritative when present; otherwise the `Origin` must
 * match exactly, and an absent one still fails closed.
 *
 * The two-signal form is required, not belt-and-braces. This seam guards **GET**
 * as well as mutations — `/_api/fetch/*` spends a connection credential and
 * returns third-party data on a GET, so a cross-origin GET riding the victim's
 * session is a real exfiltration path and cannot be exempted the way
 * `data-handler`'s reads are. But a same-origin `fetch()` GET carries **no**
 * `Origin` header at all, so an Origin-only check rejected every legitimate
 * browser read through the proxy. Fetch Metadata is the signal that covers both.
 *
 * Note a non-browser client (curl) sends neither header and is still refused;
 * one that sets `Sec-Fetch-Site: same-origin` by hand is not a CSRF vector — it
 * already holds the session cookie, which is the thing CSRF exists to exploit
 * *without* holding.
 *
 * A navigation is refused outright, before either signal is consulted — see
 * {@link isDocumentRequest}. Even a *same-origin* one: the app could fetch and
 * render the same bytes itself, so this costs it nothing, and it means the
 * "upstream HTML runs in the app origin" amplifier has no reachable entry point
 * rather than one gated on a header comparison.
 */
export function makeSameOriginCheck(config: EdgeConfig): OriginCheck {
  return (req, entry) =>
    !isDocumentRequest(req) &&
    !isWorkerRegistrationRequest(req) &&
    (fetchMetadataSameOrigin(req.headers["sec-fetch-site"]) ??
      isSameOrigin(req.headers.origin, config, entry.slug));
}

/**
 * CSRF guard for a top-level **form POST** (the shared-password login). Unlike
 * the fetch()-driven mutations above — which always carry `Origin`, so
 * {@link isSameOrigin}'s missing-fails-closed posture is right — a same-origin
 * HTML form navigation legitimately *omits* `Origin` in several browsers
 * (Firefox, Safari, some Chrome configs). So:
 *
 *  - `Sec-Fetch-Site`, where present, is authoritative (all current browsers):
 *    accept `same-origin`/`none`, reject `same-site` (sibling subdomain) and
 *    `cross-site`.
 *  - Otherwise (older browsers): a *present* `Origin` must match; an *absent*
 *    one is necessarily same-origin — a cross-origin POST always sends `Origin`,
 *    which an attacker cannot strip — so it is accepted.
 */
export function isSameOriginFormPost(
  originHeader: string | string[] | undefined,
  secFetchSite: string | string[] | undefined,
  config: EdgeConfig,
  slug: string,
): boolean {
  if (typeof secFetchSite === "string" && secFetchSite !== "") {
    return secFetchSite === "same-origin" || secFetchSite === "none";
  }
  if (originHeader === undefined) return true;
  return isSameOrigin(originHeader, config, slug);
}

/**
 * Whether this deployment permits an app in the given visibility mode at all.
 * `public` and `password` are open-to-the-internet surfaces an operator can
 * forbid per deployment (`EDGE_ALLOW_*_APPS`); `internal`/`group` are SSO-gated
 * and always permitted. This is an operator policy check, distinct from the
 * per-session {@link visibilityAllows} authorization check below.
 */
export function visibilityModeAllowed(
  mode: RegistryEntry["visibilityMode"],
  config: EdgeConfig,
): boolean {
  if (mode === "public") return config.allowPublicApps;
  if (mode === "password") return config.allowPasswordApps;
  return true;
}

/**
 * Does this session's group snapshot satisfy the app's visibility rule?
 *
 * Deny-by-default: the fall-through refuses any mode not handled above, so a
 * visibility label the projection carries but this gate does not understand —
 * a newly added enum value, or a stale replica reading a renamed one — fails
 * closed rather than serving the app. That property is what makes it safe to
 * add modes to the enum (`private`, once it exists) ahead of the gate.
 */
export function visibilityAllows(entry: RegistryEntry, groups: string[]): boolean {
  // `internal` is "any authenticated principal in the directory" — a session is
  // itself sufficient, and *which* user holds it is deliberately not consulted.
  if (entry.visibilityMode === "internal") return true;
  if (entry.visibilityMode === "group") {
    // Any-of (ADR-0040 §5): membership in ANY listed group opens the app. An
    // empty list denies — the same fail-closed answer the nullable scalar gave
    // before it, and the reason a zero-group app is a representable state rather
    // than a validation error.
    //
    // The `Array.isArray` guard is not belt-and-braces over the projection's
    // normalizer. This gate is the last line, and the types cannot cover the ways
    // a malformed value reaches it — a replica running older projection code, a
    // hand-run SQL fix, a future writer that skips the mapper. Without the guard
    // a non-array THROWS, and a throw inside the request path is a 500, not a
    // denial: it would surface as an outage on a working app rather than as the
    // closed door this function's whole contract promises.
    //
    // Linear scan, not a Set: the cap is 10 groups (MAX_VISIBILITY_GROUPS) and a
    // session snapshot is small, so building two Sets per request would cost more
    // than it saves on the hottest authorization path in the platform.
    return (
      Array.isArray(entry.visibilityGroupIds) &&
      entry.visibilityGroupIds.some((id) => groups.includes(id))
    );
  }
  // A `password` session is itself proof of the password — it could only have
  // been minted by the /_auth/login challenge (passwordLogin.ts). The OIDC
  // callback never resolves password apps, so this branch is gate-only.
  if (entry.visibilityMode === "password") return true;
  return false; // public never passes the session gate; unknown modes deny
}
