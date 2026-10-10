import { z } from "zod";

import { ProviderRefSchema } from "./providers.js";

/**
 * The fetch-proxy wire contract (design doc `docs/design/fetch-proxy.md`).
 *
 * Apps call `fetch('/_api/fetch/https://api.example.com/...')` — same-origin, so
 * it satisfies `connect-src 'self'` with no CSP widening; method, safelisted
 * headers, and body pass through, and the response streams back unchanged
 * (§3.1). The edge enforces policy and forwards to `helix-egress` over an internal
 * HTTP seam carrying the attested instruction; egress performs the call. The
 * shapes here are the small pieces both services (and tests) share — there is no
 * JSON envelope, because the proxy is transparent and streaming.
 */

/** Same-origin path prefix the edge serves the proxy on. */
export const FETCH_PROXY_PREFIX = "/_api/fetch/";

function safeDecode(s: string): string | null {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

/**
 * Extract the target URL from a `/_api/fetch/<url>` request URL — raw first,
 * then percent-decoded, so both shapes the shim and hand-written callers
 * produce resolve to the same target. `indexOf` rather than `startsWith`: the
 * dev gateway serves the same handler under `/:slug/_api/fetch/*`.
 *
 * Shared because two callers must agree on what "the target" is: the gateway
 * authorizes it against the manifest (`apps/edge/src/gateway/fetch.ts`) and the
 * log serializer redacts it (`@azx-pbc/shared/logging`). If those two ever
 * parsed differently, the log would describe a call the edge didn't make.
 */
export function parseFetchTarget(rawUrl: string): URL | null {
  const i = rawUrl.indexOf(FETCH_PROXY_PREFIX);
  if (i === -1) return null;
  const tail = rawUrl.slice(i + FETCH_PROXY_PREFIX.length);
  if (!tail) return null;
  for (const candidate of [tail, safeDecode(tail)]) {
    if (candidate === null) continue;
    try {
      const url = new URL(candidate);
      if (url.protocol === "https:" || url.protocol === "http:") return url;
    } catch {
      // try the next candidate
    }
  }
  return null;
}

// ── Internal edge → egress transport (control via headers; bodies stream) ─────

/** Carries the signed attested instruction JWT (edge → egress). */
export const INSTRUCTION_HEADER = "x-helix-instruction";
/** The full target URL the edge authorized (egress checks origin == instruction.origin). */
export const TARGET_HEADER = "x-helix-target";
/** The upstream HTTP method to use (egress preserves the app's method). */
export const METHOD_HEADER = "x-helix-method";
/**
 * Egress → edge: the outcome label for the edge to meter into `gateway_calls`.
 * Values (by convention — the edge's `toOutcome` folds anything unrecognized
 * into `error`): `ok` a clean proxied round-trip; `upstream_throttled` the
 * upstream answered 429 (the proxy worked, the vendor said slow down);
 * `refusal` egress itself refused the call (4xx from `fail`, and the delegated
 * `provider_unavailable` / `provider_misconfigured` codes, which meter as
 * `refusal`); `error` an egress-side failure (5xx
 * from `fail`, a throw, a temporary renewal failure); and
 * `connection_required`, the delegated answer for "the caller has no usable
 * connection to the bound provider", which the edge ledgers under its OWN
 * label so usage accounting separates "user not connected" from "policy
 * refused".
 */
export const OUTCOME_HEADER = "x-helix-egress-outcome";

/**
 * Request headers the proxy forwards upstream. Everything else is dropped —
 * notably `cookie` and `authorization` (the app must not smuggle the session
 * cookie outbound nor override the injected credential) and hop-by-hop headers
 * (§6). Lowercase for case-insensitive comparison.
 *
 * `anthropic-version` is here for the `llm` capability: the edge sets it as a
 * constant on the vendor call it routes through egress. It is a benign API
 * version string — allowing an app to send it on a `fetch` call is meaningless.
 */
export const REQUEST_HEADER_SAFELIST: readonly string[] = [
  "accept",
  "accept-language",
  "anthropic-version",
  "content-type",
  "if-modified-since",
  "if-none-match",
  "user-agent",
];

/**
 * Strip upstream credential and transport headers before returning to the app.
 * Authorization is a static backstop; egress also removes every header named by
 * the injection recipe, including custom and HMAC timestamp/signature headers.
 * Keep www-authenticate, which carries an upstream challenge.
 *
 * Strip Location so browsers cannot follow a redirect outside the proxy;
 * egress also does not follow redirects (ADR-0005). Keep Content-Location,
 * which does not navigate, but redact any injected query credential in it.
 *
 * Policy and reporting headers belong to the app origin, not a vendor. The
 * gateway's response is same-origin with the app, so a copied clear-site-data
 * or nel applies to the app's origin even on a fetch() response (clearing its
 * cookies and storage, or registering a reporting policy). Navigations that would
 * treat the body as a document are refused on `/_api/fetch/*`; worker-destination
 * loads and `Service-Worker` registration fetches are refused too. The edge still
 * sets a backstop `content-security-policy: default-src 'none'` on every proxied
 * response so a misclassified load cannot inherit vendor policy. Strip upstream
 * CSP and reporting headers here anyway — they must never replace the app CSP.
 * Keep this a denylist; an allowlist would drop headers apps rely on (etag,
 * retry-after, rate-limit headers).
 */
export const RESPONSE_HEADER_BLOCKLIST: readonly string[] = [
  "set-cookie",
  "set-cookie2",
  "authorization",
  "location",
  "transfer-encoding",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "trailer",
  "upgrade",
  "clear-site-data",
  "content-security-policy",
  "content-security-policy-report-only",
  "refresh",
  "report-to",
  "reporting-endpoints",
  "nel",
  "service-worker-allowed",
  "alt-svc",
];

// ── App-facing error shape ────────────────────────────────────────────────────

/**
 * Error codes the proxy returns as JSON (the app's `fetch` resolves with the
 * status + this body) when the call is refused before/instead of an upstream
 * response. `blocked` is an SSRF refusal; `bad_target` a malformed/undecodable
 * target; `too_large` a request body over the size cap (413, refused before the
 * upstream call); `replay` a re-presented attested instruction whose one-time
 * `jti` was already burned (409, refused at egress before any upstream call —
 * ADR-0013 Step 1, issue #3); `upstream_error` an egress/transport failure. (A
 * *response* over the cap cannot use this code — status + headers are already
 * flushed by the time the byte counter trips, so the body is truncated instead;
 * see issue #8 and `@azx-pbc/shared` `capBody`.)
 *
 * The delegated-call codes name why a provider-bound call could not be
 * served, each distinguishable from a consent problem: `connection_required`
 * (403) — no or dead connection, a definitive grant rejection, an uncertain
 * rotation, or a caller that can never hold a connection (anonymous,
 * shared-password); the body carries {@link FetchErrorProvider} so the app can
 * offer Connect. `provider_unavailable` (503) — the provider was deleted or its
 * binding blocked by a sensitive edit. `provider_misconfigured` (502) — invalid
 * provider configuration; administrator action required. The first code is a
 * consent problem and the other two are not — that is the distinction the
 * ledger's `connection_required` outcome label tracks.
 *
 * Every code's message is a fixed platform string — never vendor error content,
 * credentials, or internal detail.
 */
export const FETCH_ERROR_CODES = [
  "forbidden",
  "rate_limited",
  "bad_target",
  "blocked",
  "too_large",
  "replay",
  "upstream_error",
  "connection_required",
  "provider_unavailable",
  "provider_misconfigured",
] as const;
export const FetchErrorCodeSchema = z.enum(FETCH_ERROR_CODES);
export type FetchErrorCode = z.infer<typeof FetchErrorCodeSchema>;

/**
 * Provider metadata on a delegated-call error — sufficient for the app to offer
 * Connect: which provider to reference and, when the
 * platform can name it, what to call it. Keys are bounded by a **strict** object
 * — an unknown key fails the parse, not a silent strip — so credential-shaped
 * fields (`accessToken`, `client_secret`, …) cannot ride the error body to the
 * app. `ref` is the same reference manifests and the catalogue key on;
 * `displayName` mirrors the provider row's bound.
 */
export const FetchErrorProviderSchema = z.strictObject({
  ref: ProviderRefSchema,
  displayName: z.string().min(1).max(200).optional(),
});
export type FetchErrorProvider = z.infer<typeof FetchErrorProviderSchema>;

export const FetchProxyErrorSchema = z.object({
  code: FetchErrorCodeSchema,
  message: z.string(),
  /** Present only on the delegated-call codes that carry it (`connection_required`, `provider_unavailable`). */
  provider: FetchErrorProviderSchema.optional(),
});
export type FetchProxyError = z.infer<typeof FetchProxyErrorSchema>;
