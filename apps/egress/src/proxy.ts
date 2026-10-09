import { type IncomingHttpHeaders } from "node:http";
import {
  context,
  propagation,
  ROOT_CONTEXT,
  SpanKind,
  SpanStatusCode,
  trace,
} from "@opentelemetry/api";
import { Agent, request } from "undici";
import type { FastifyReply, FastifyRequest } from "fastify";
import {
  type AttestedInstruction,
  type FetchErrorCode,
  type InjectionRecipe,
  type TokenPlacement,
  INSTRUCTION_HEADER,
  METHOD_HEADER,
  OUTCOME_HEADER,
  REQUEST_HEADER_SAFELIST,
  RESPONSE_HEADER_BLOCKLIST,
  TARGET_HEADER,
  parseHmacCredential,
} from "@azx-pbc/shared";
import { capBody } from "@azx-pbc/shared/bodyCap";
import { hmacTimestampNow, renderHmacAuth, signTimestamp, substitute } from "./hmac.js";
import { verifyInstruction } from "./instruction.js";
import { RecipeDriftError, type SecretResolver } from "./secrets.js";
import { type InstructionBurnStore } from "./burn.js";
import type { DelegatedResolution, DelegatedResolver } from "./delegated.js";
import {
  ATTR_APP_ID,
  ATTR_CAPABILITY,
  ATTR_CLIENT_DISCONNECTED,
  ATTR_CONNECTION,
  ATTR_CREDENTIAL_SOURCE,
  ATTR_ENV,
  ATTR_METHOD,
  ATTR_OUTCOME,
  ATTR_PROVIDER_REF,
  ATTR_TARGET_ORIGIN,
  ATTR_TARGET_PATH,
  ATTR_UPSTREAM_STATUS,
  SPAN_EGRESS_PROXY,
} from "@azx-pbc/shared/telemetry";
import { instruments, tracer } from "./telemetry.js";
import { egressSpanAttributes } from "./spanAttributes.js";
import { SsrfBlockedError, makeValidatingConnector } from "./ssrf.js";

/**
 * `POST /proxy` — the one route that touches plaintext secrets and the public
 * internet (architecture §3, fetch-proxy design §6/§7). It trusts the edge's
 * attested instruction, resolves a connection secret if named, applies SSRF
 * controls, injects the credential server-side, and streams the upstream
 * response straight back. Internal-only: never exposed to app users.
 */

export interface ProxyDeps {
  instructionKey: Buffer;
  /** null ⇒ no secret store configured; secret-backed calls are refused. */
  resolver: SecretResolver | null;
  /** null ⇒ replay protection disabled (tests only); prod always sets it. */
  burnStore: InstructionBurnStore | null;
  limits: { maxBodyBytes: number; timeoutMs: number };
  /** Dev/test seam — permit private/loopback targets (false in prod & adversarial tests). */
  allowPrivate: boolean;
  /** Dev/test seam — permit secret injection into a cleartext http target (false in prod). */
  allowInsecureConnection: boolean;
  /**
   * Builds the delegated resolution against the proxy's shared
   * dispatcher — the renewer's vendor calls ride the same pinned transport.
   * null/omitted ⇒ delegated instructions are refused fail-closed (the
   * mechanism not wired is an egress misconfiguration, answered as such).
   */
  delegated?: (dispatcher: Agent) => DelegatedResolver | null;
}

const REQUEST_SAFE = new Set(REQUEST_HEADER_SAFELIST);
const RESPONSE_BLOCKED = new Set(RESPONSE_HEADER_BLOCKLIST);
const BODYLESS = new Set(["GET", "HEAD"]);

function fail(reply: FastifyReply, status: number, code: FetchErrorCode, message: string): void {
  reply.header(OUTCOME_HEADER, status >= 500 ? "error" : "refusal");
  reply.code(status).send({ code, message });
}

/**
 * The delegated-call refusal — the same fixed-body shape as `fail()` plus the
 * optional provider metadata, with the OUTCOME HEADER made EXPLICIT. `fail()`
 * derives the label from the status, and the delegated codes break that
 * mapping in both directions: `connection_required` is a 403 whose ledger
 * label is its own new word (not `refusal`), and `provider_unavailable` /
 * `provider_misconfigured` are 5xx whose ledger label is `refusal` (not
 * `error`).
 */
function failDelegated(reply: FastifyReply, resolution: DelegatedResolution & { ok: false }): void {
  reply.header(OUTCOME_HEADER, resolution.outcome);
  reply
    .code(resolution.status)
    .send(
      resolution.provider
        ? { code: resolution.code, message: resolution.message, provider: resolution.provider }
        : { code: resolution.code, message: resolution.message },
    );
}

/** Forward only the safelisted request headers; cookie/authorization never go out. */
function safeRequestHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (REQUEST_SAFE.has(k) && typeof v === "string") out[k] = v;
  }
  return out;
}

/**
 * What `applyInjection` wrote into the outbound request, so the response loop can
 * strip exactly that back out (issue #7). The `header` and `hmac-timestamp`
 * recipes take arbitrary configured names, so a static blocklist can never
 * enumerate every credential header — only recording what we injected covers it.
 *
 * `headerNames` is a list because `hmac-timestamp` writes two (the timestamp and
 * the signature). The strip set is built from exactly this list, so the property
 * holds by construction: whatever we wrote, we strip.
 */
interface Injected {
  headerNames: readonly string[];
  queryParam: string | null;
}

const NOTHING_INJECTED: Injected = { headerNames: [], queryParam: null };

/**
 * Apply the DELEGATED access token to the outbound request per the provider's
 * configured placement — `Authorization: Bearer` (the default) or the one
 * named header, verbatim. A delegated token has no query
 * and no signing recipe by construction (`TokenPlacementSchema` refuses
 * them): it is the user's credential, and neither a logged URL nor a signing
 * recipe is an acceptable presentation for it. The recorded `headerNames`
 * feed the response reflection strip exactly as the static recipes' do.
 */
function applyTokenPlacement(
  headers: Record<string, string>,
  placement: TokenPlacement,
  token: string,
): Injected {
  if (placement.kind === "header-bearer") {
    headers["authorization"] = `Bearer ${token}`;
    return { headerNames: ["authorization"], queryParam: null };
  }
  headers[placement.name] = token;
  return { headerNames: [placement.name], queryParam: null };
}

/**
 * Apply the resolved credential to the outbound request.
 *
 * Recipe header names are normalised to lowercase by the schema, so the names
 * recorded here always match the lowercased keys of an upstream response — which
 * is what makes the reflection strip below able to find them.
 *
 * May throw (a malformed `hmac-timestamp` blob). The caller contains that: the
 * message can carry credential material, so it must reach neither the app nor the
 * log.
 */
function applyInjection(
  target: URL,
  headers: Record<string, string>,
  recipe: InjectionRecipe,
  value: string,
): Injected {
  switch (recipe.kind) {
    case "header-bearer":
      headers["authorization"] = `Bearer ${value}`;
      return { headerNames: ["authorization"], queryParam: null };
    case "header": {
      headers[recipe.name] = substitute(recipe.template, "{}", value);
      return { headerNames: [recipe.name], queryParam: null };
    }
    case "query":
      target.searchParams.set(recipe.param, value);
      return { headerNames: [], queryParam: recipe.param };
    case "hmac-timestamp": {
      const { credential, key } = parseHmacCredential(value);
      // One clock reading, used for both the signature and the header: two reads
      // would sign a timestamp that was never transmitted.
      const timestamp = hmacTimestampNow();
      headers[recipe.timestampHeader] = timestamp;
      headers[recipe.authHeader] = renderHmacAuth(
        recipe.template,
        credential,
        signTimestamp(key, timestamp),
      );
      return {
        headerNames: [recipe.timestampHeader, recipe.authHeader],
        queryParam: null,
      };
    }
  }
}

/**
 * Header names whose values are URLs that could echo back an injected query secret.
 * `location` is NOT here — it is stripped wholesale by the response blocklist so the
 * browser can't follow the redirect (ADR-0005, issue #10); only `content-location`
 * (which doesn't drive navigation) survives to be redacted.
 */
const URL_VALUED_RESPONSE_HEADERS = new Set(["content-location"]);

/**
 * Redact an injected `query`-recipe secret from a URL-valued response header
 * (issue #7). An upstream that reflects the request URL in `Content-Location`
 * would otherwise carry `?<param>=<secret>` back to the app. Leaves other headers
 * untouched; if the value doesn't parse as a URL carrying the param, returns it
 * unchanged (a relative URL can't be resolved without the request base, so a param
 * match there is dropped by returning "REDACTED" only on parse hits).
 */
function redactQueryParam(
  name: string,
  value: string | string[],
  param: string,
): string | string[] {
  if (!URL_VALUED_RESPONSE_HEADERS.has(name)) return value;
  const redactOne = (raw: string): string => {
    try {
      // Allow relative URLs by resolving against a throwaway base.
      const url = new URL(raw, "https://redacted.invalid");
      if (!url.searchParams.has(param)) return raw;
      url.searchParams.set(param, "REDACTED");
      // Preserve relative form: strip the throwaway base back off.
      return raw.startsWith(url.origin) ? url.href : url.href.slice(url.origin.length);
    } catch {
      return raw;
    }
  };
  return Array.isArray(value) ? value.map(redactOne) : redactOne(value);
}

/** What `proxyHandler` establishes before it decides the span's parent. */
interface AuthenticatedRequest {
  instruction: AttestedInstruction;
  targetRaw: string;
  method: string;
}

/**
 * Authentication result, carrying the refusal rather than collapsing every
 * failure to one status: a *missing* instruction or target is a malformed
 * request (400 `bad_target`), while a present-but-unverifiable one is a
 * rejection (401 `forbidden`). The two are different signals to whoever is
 * debugging the edge, and `proxy.test.ts` pins both.
 */
type AuthOutcome =
  | { ok: true; value: AuthenticatedRequest }
  | { ok: false; status: number; code: FetchErrorCode; message: string };

export interface ProxyHandler {
  handler: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
  /** The shared dispatcher — close it on app teardown to drain pooled sockets. */
  dispatcher: Agent;
}

export function makeProxyHandler(deps: ProxyDeps): ProxyHandler {
  // One shared dispatcher for the process lifetime: the SSRF validate-and-pin
  // moved into the connector (see makeValidatingConnector), so pooling/keep-alive
  // is recovered without losing the IP-pin (ADR-0005 perf note). Redirects are
  // still NEVER followed: undici 7 chases a redirect only when a `redirect`
  // interceptor is composed onto the dispatcher, and we compose none — a plain
  // Agent returns the 3xx verbatim (belt-and-suspenders, `Location` is also
  // stripped by the response blocklist so the browser can't chase it — issue #10).
  const dispatcher = new Agent({
    connect: makeValidatingConnector(deps.allowPrivate, deps.limits.timeoutMs),
    headersTimeout: deps.limits.timeoutMs,
    bodyTimeout: deps.limits.timeoutMs,
  });

  // The delegated resolution, built against the shared
  // dispatcher so the renewer's vendor calls ride the same pinned transport.
  const delegated = deps.delegated?.(dispatcher) ?? null;

  /**
   * Header reads + instruction verification, and nothing else.
   *
   * `null` means "not authenticated" — the caller turns that into the 401. Kept
   * separate from {@link runProxy} so the span's parent can be decided on the
   * result, which is the whole point of the split.
   */
  async function authenticate(req: FastifyRequest): Promise<AuthOutcome> {
    const token = req.headers[INSTRUCTION_HEADER];
    const targetRaw = req.headers[TARGET_HEADER];
    if (typeof token !== "string" || typeof targetRaw !== "string") {
      return {
        ok: false,
        status: 400,
        code: "bad_target",
        message: "missing instruction or target",
      };
    }

    const instruction = await verifyInstruction(token, deps.instructionKey);
    if (!instruction) {
      return { ok: false, status: 401, code: "forbidden", message: "invalid attested instruction" };
    }

    return {
      ok: true,
      value: {
        instruction,
        targetRaw,
        method: (req.headers[METHOD_HEADER] ?? "GET").toString().toUpperCase(),
      },
    };
  }

  /**
   * The authorized half. Everything here runs with a verified instruction —
   * authentication happened in `proxyHandler`, which is also what decides
   * whether this call is allowed to join the edge's trace (see there).
   */
  async function runProxy(
    req: FastifyRequest,
    reply: FastifyReply,
    authenticated: AuthenticatedRequest,
  ): Promise<void> {
    const { instruction, targetRaw, method } = authenticated;

    // The edge hangs up (its own client left, or it hit its deadline): stop waiting for
    // the vendor. Watch the response, not the request: req.raw 'close' fires once the
    // inbound body is drained. writableEnded, not writableFinished: light-my-request never
    // settles the latter.
    const abort = new AbortController();
    let clientGone = false;
    let requestCapTripped = false;
    const onClose = (): void => {
      // A request-cap trip destroys req.raw, which may close this socket too. That is our
      // own cut, not a hang-up, and the catch below must still answer 413.
      if (reply.raw.writableEnded || requestCapTripped) return;
      clientGone = true;
      abort.abort();
    };
    reply.raw.once("close", onClose);
    // proxyHandler awaits authenticate() before this function runs, so the socket can
    // already be gone and 'close' will never fire again. A destroyed response with no
    // end() is the same hang-up. Verified with a scratch script on Node 24 (not a unit test:
    // no deterministic way to hang up in the gap before this listener is attached).
    if (reply.raw.destroyed && !reply.raw.writableEnded) onClose();

    // One-time use: burn the jti before doing any work, so a captured
    // instruction re-POSTed inside its TTL is refused before the secret is
    // resolved or the upstream is dialed (ADR-0013 Step 1, issue #3). An empty
    // insert result means the jti was already spent — a replay.
    if (deps.burnStore && !(await deps.burnStore.burn(instruction.requestId))) {
      return fail(reply, 409, "replay", "attested instruction already used");
    }

    // Edge-signed claims only: the edge matched this origin against the app's
    // manifest allowlist before signing, so these are values the operator
    // granted rather than values the app chose.
    trace.getActiveSpan()?.setAttributes(
      egressSpanAttributes({
        [ATTR_APP_ID]: instruction.appId,
        [ATTR_ENV]: instruction.env,
        [ATTR_CAPABILITY]: instruction.capability,
        [ATTR_TARGET_ORIGIN]: instruction.origin,
        [ATTR_TARGET_PATH]: instruction.path,
        [ATTR_METHOD]: method,
        [ATTR_CONNECTION]: instruction.connection,
      }),
    );

    let target: URL;
    try {
      target = new URL(targetRaw);
    } catch {
      return fail(reply, 400, "bad_target", "target is not a valid URL");
    }
    if (target.protocol !== "https:" && target.protocol !== "http:") {
      return fail(reply, 400, "bad_target", "only http(s) targets are proxied");
    }
    // Authority validation (bug-class ledger: a secret-bearing request must
    // never ride a URL whose authority it doesn't own). `URL.origin` ignores
    // userinfo, so the origin binding below cannot see `user:pass@` — and
    // undici silently dials such a URL rather than refusing it. Credentials
    // live in the connection store, never the target string; refuse instead of
    // normalizing.
    if (target.username !== "" || target.password !== "") {
      return fail(reply, 400, "bad_target", "target must not carry userinfo credentials");
    }
    // The instruction binds the origin the edge authorized — egress re-checks it.
    if (target.origin !== instruction.origin) {
      return fail(reply, 403, "forbidden", "target origin does not match the authorization");
    }
    // ...and (ADR-0013 step 2, issue #6) the method + pathname, so a captured
    // instruction can't be redirected to a different verb/resource on that origin.
    // Assert only when bound (an old-edge instruction may omit them — rollout
    // safety; only the edge can sign, so absence isn't tampering).
    if (instruction.method !== undefined && instruction.method !== method) {
      return fail(reply, 403, "forbidden", "method does not match the authorization");
    }
    if (instruction.path !== undefined && instruction.path !== target.pathname) {
      return fail(reply, 403, "forbidden", "path does not match the authorization");
    }

    // Request body cap, fast-path: a truthful oversized content-length is
    // refused before we resolve a secret or dial out. The real enforcement is
    // the byte counter on the re-stream below — this only avoids wasted work
    // (issue #8).
    if (!BODYLESS.has(method)) {
      const declared = Number(req.headers["content-length"]);
      if (Number.isFinite(declared) && declared > deps.limits.maxBodyBytes) {
        return fail(reply, 413, "too_large", "request body exceeds the size cap");
      }
    }

    const headers = safeRequestHeaders(req.headers);

    // Resolve + inject the connection secret, if this call is secret-backed.
    let injected = NOTHING_INJECTED;
    // Set for a recipe whose credential is derived from the local clock, so the
    // response can be checked for skew (see below).
    let clockDerived = false;
    // Set when the call dispatched on a DELEGATED token — the connection row
    // the pre-expiry-401 flag targets if the vendor answers 401 before expiry.
    let delegatedDispatch: { connectionId: string } | null = null;
    if (instruction.connection) {
      // A connection secret must never cross the wire in cleartext. Egress is the
      // credential broker, so it enforces this independently of the edge's origin
      // allowlist — an http origin approved as a connection binding is still
      // refused here (issue #11, ADR-0005). The secret is not even resolved for a
      // cleartext target. `allowInsecureConnection` is a dev/test-only seam.
      if (target.protocol !== "https:" && !deps.allowInsecureConnection) {
        return fail(reply, 403, "forbidden", "secret-backed calls require https");
      }
      if (!deps.resolver) {
        return fail(reply, 502, "upstream_error", "secret store not configured");
      }
      // Resolution can now fail on the network (Key Vault) or on custody (RBAC,
      // a material referencing a deleted vault entry), not just return "no such
      // connection". Contain it here: an uncaught throw would reach Fastify's
      // default handler as a 500 whose body could echo the vault host or secret
      // name back to the untrusted app. Log the detail, return an opaque 502.
      let resolved: Awaited<ReturnType<typeof deps.resolver.resolve>>;
      try {
        resolved = await deps.resolver.resolve(
          instruction.appId,
          instruction.connection,
          instruction.capability,
          instruction.env,
          instruction.origin,
        );
      } catch (err) {
        if (err instanceof RecipeDriftError) {
          // Not a custody failure. Logging it beside the vault probes below would
          // point an operator at Key Vault for a bad row, so it gets the same
          // `reason` code the injection guard uses — the two are the same class of
          // fault, caught at different depths.
          req.log.error(
            {
              appId: instruction.appId,
              connection: instruction.connection,
              reason: "injection_failed",
            },
            "stored connection secret does not fit its injection recipe",
          );
          return fail(reply, 502, "upstream_error", "connection secret unavailable");
        }
        // Surface the vault's own status/code explicitly. `KeyVaultError` carries them
        // precisely so an operator can tell 403-RBAC from 403-SecretDisabled, and
        // 404-integrity (a row referencing a deleted entry) from a transport failure —
        // none of which is deducible from the opaque 502 the app receives.
        const kv = err as { status?: unknown; code?: unknown };
        req.log.error(
          {
            err,
            appId: instruction.appId,
            connection: instruction.connection,
            vaultStatus: typeof kv.status === "number" ? kv.status : undefined,
            vaultCode: typeof kv.code === "string" ? kv.code : undefined,
          },
          "connection secret resolution failed",
        );
        return fail(reply, 502, "upstream_error", "connection secret unavailable");
      }
      if (!resolved) {
        return fail(reply, 403, "forbidden", "connection not found or not granted");
      }
      // Sealed row vs minted Entra token (ADR-0046) — two bounded values, and
      // the tell an operator needs when a Foundry-bound call misauthenticates.
      if (resolved.source) {
        trace
          .getActiveSpan()
          ?.setAttributes(egressSpanAttributes({ [ATTR_CREDENTIAL_SOURCE]: resolved.source }));
      }
      clockDerived = resolved.injection.kind === "hmac-timestamp";
      try {
        injected = applyInjection(target, headers, resolved.injection, resolved.value);
      } catch {
        // Deliberately binds nothing. A throw here means the material did not fit
        // its recipe (an `hmac-timestamp` blob that isn't one), and the message
        // can carry credential material — V8 embeds a ~10-character prefix of its
        // input in a `JSON.parse` error, which for this value is the start of a
        // private key. A `reason` code is the whole diagnostic value; the message
        // would add only leak surface, to the log as well as the response. This is
        // the opposite call from the resolve `catch` above, where the Key Vault
        // status/code genuinely carry operator signal and carry no secret.
        req.log.error(
          {
            appId: instruction.appId,
            connection: instruction.connection,
            recipe: resolved.injection.kind,
            reason: "injection_failed",
          },
          "connection secret could not be applied to the outbound request",
        );
        // The same opaque 502 as a resolution failure: an app must not be able to
        // probe *why* a credential did not work.
        return fail(reply, 502, "upstream_error", "connection secret unavailable");
      }
    } else if (instruction.provider) {
      // ── The delegated branch ───────────────────────────────────────────────────────────
      // The instruction carries a provider ref, not a secret name: resolve
      // the CALLER'S connection for (userOid, providerRef, env), renew if
      // due, and inject the access token per the provider's placement. The
      // resolution's refusals are dispatch-before-refusal — no vendor traffic
      // of any kind fires behind them — and never fall back to another
      // user's connection, a static secret, or an unauthenticated call.
      //
      // The same cleartext rule as the secret path: a delegated access token
      // must never cross the wire in cleartext (the fixture vendor is http —
      // the dev/test seam opens it, prod refuses).
      if (target.protocol !== "https:" && !deps.allowInsecureConnection) {
        return fail(reply, 403, "forbidden", "delegated calls require https");
      }
      if (!delegated) {
        return fail(reply, 502, "upstream_error", "delegated resolution not configured");
      }
      let resolution: DelegatedResolution;
      try {
        if (instruction.userKind === undefined) {
          // Unreachable: the strict instruction parse refuses a provider
          // instruction without the caller kind. Guarded fail-closed anyway —
          // an identity this plane cannot name is never served a delegated
          // call, and the reason rides the bounded log word only.
          req.log.warn(
            { appId: instruction.appId, provider: instruction.provider, reason: "identity_absent" },
            "delegated instruction carried no caller kind",
          );
          return fail(reply, 502, "upstream_error", "delegated credential unavailable");
        }
        resolution = await delegated.resolve(
          {
            userOid: instruction.userOid,
            // The caller-kind discrimination never infers identity from
            // userOid's shape — the edge records the kind.
            userKind: instruction.userKind,
            providerRef: instruction.provider,
            env: instruction.env,
          },
          target.origin,
        );
      } catch {
        // An unexpected throw inside resolution (a DB failure beyond the
        // resolver's own containment). Contained to the opaque 502 like the
        // secret path's resolve guard — the log carries no error text: this
        // plane's error paths can embed credential material.
        req.log.warn(
          {
            appId: instruction.appId,
            provider: instruction.provider,
            reason: "resolution_failed",
          },
          "delegated resolution failed unexpectedly",
        );
        return fail(reply, 502, "upstream_error", "delegated credential unavailable");
      }
      if (!resolution.ok) {
        req.log.warn(
          {
            appId: instruction.appId,
            provider: instruction.provider,
            reason: resolution.spanOutcome,
          },
          "delegated call refused before dispatch",
        );
        return failDelegated(reply, resolution);
      }

      // The caller's connection resolved. Record the plane's two delegated
      // dimensions — where the credential came from, and which provider —
      // and inject the token into the configured placement. The token value
      // itself never enters a span, a log field, or the response.
      trace.getActiveSpan()?.setAttributes(
        egressSpanAttributes({
          [ATTR_CREDENTIAL_SOURCE]: "delegated",
          [ATTR_PROVIDER_REF]: resolution.provider.ref,
        }),
      );
      injected = applyTokenPlacement(
        headers,
        resolution.provider.tokenPlacement,
        resolution.accessToken,
      );
      // The pre-expiry-401 arm: a vendor 401 on THIS dispatch sets the
      // renew-before-next flag (below, at the response head).
      delegatedDispatch = { connectionId: resolution.connectionId };
    }

    // SSRF: the shared dispatcher's connector resolves + validates every address
    // and pins the socket to it (see makeValidatingConnector) — a blocked or
    // unresolvable host throws SsrfBlockedError, surfaced on the `request()`
    // rejection below and mapped to 403 `blocked`.

    // Count the request bytes on the way out: a chunked / CL-absent / lying-CL
    // upload can't stream unbounded egress-billed bandwidth past the cap. A trip
    // destroys req.raw and errors the undici upload → the catch maps it to 413.
    const requestBody = BODYLESS.has(method)
      ? undefined
      : capBody(req.raw, deps.limits.maxBodyBytes, "request", () => {
          requestCapTripped = true;
        });

    try {
      // Dial the real origin: undici pools by origin (keep-alive), derives the
      // Host header and TLS SNI from it, and the connector rewrites the socket
      // target to the validated IP.
      const upstream = await request(target.href, {
        method,
        headers,
        body: requestBody,
        dispatcher,
        signal: abort.signal,
      });

      // Response cap, fast-path: a truthful oversized content-length is rejected
      // cleanly (before any body is committed) without draining the connection.
      const len = Number(upstream.headers["content-length"]);
      if (Number.isFinite(len) && len > deps.limits.maxBodyBytes) {
        upstream.body.destroy();
        return fail(reply, 502, "upstream_error", "upstream response too large");
      }

      // A clock-derived credential signs `now`, so egress clock drift past the
      // upstream's tolerance makes *every* call to that origin fail — and it
      // presents as the vendor's own 401 passed through, with no reason to suspect
      // us. Nothing in-process can detect that; the upstream's own `Date` header
      // can. This turns a silent total outage into a one-line diagnosis.
      if (clockDerived) {
        const upstreamDate = Date.parse(String(upstream.headers["date"] ?? ""));
        const skewMs = Number.isNaN(upstreamDate) ? 0 : Math.abs(Date.now() - upstreamDate);
        if (skewMs > 60_000) {
          req.log.warn(
            { origin: instruction.origin, appId: instruction.appId, skewMs },
            "egress clock differs from the upstream by more than a minute — " +
              "a timestamp-signed credential will be rejected",
          );
        }
      }

      // An upstream throttle is a proxied round-trip that worked, but `ok`
      // hides it from anyone alerting on `helix.outcome` (a real 70K-vs-40K
      // TPM throttle presented as a wall of `ok` spans). Label the throttle so
      // it is filterable; the edge's `toOutcome` folds unknown labels into
      // `error`, which is the truthful ledger meaning for a call the vendor
      // refused.
      reply.header(OUTCOME_HEADER, upstream.statusCode === 429 ? "upstream_throttled" : "ok");
      reply.code(upstream.statusCode);

      // A vendor 401 on a delegated call — before or
      // after the recorded expiry — requires renewal before the NEXT app
      // request. The response itself passes through byte-unchanged below (no
      // replay: Helix never re-sends the call), and the flag is set
      // fire-and-forget so the vendor's answer streams immediately; the
      // status-CAS'd, column-scoped UPDATE cannot resurrect a dead row, and a
      // failed write costs only one extra renewal later.
      if (delegatedDispatch && upstream.statusCode === 401 && delegated) {
        delegated.flagRenewBeforeNext(delegatedDispatch.connectionId);
      }
      // Dynamically strip the exact headers we injected so an upstream that
      // reflects them (echo/debug endpoints, CORS reflection) can't leak the
      // credential back to the app (issue #7). This covers the arbitrary
      // configured names — the `header` recipe's, and `hmac-timestamp`'s
      // timestamp and signature headers — that no static blocklist could
      // enumerate. For `hmac-timestamp` the reflected pair is not the private key,
      // but it *is* a working credential for the upstream's whole clock-skew
      // window against any path on that origin, re-harvestable on every call —
      // outside the manifest allowlist, the budget, and `gateway_calls`.
      const stripped = injected.headerNames.length
        ? new Set([...RESPONSE_BLOCKED, ...injected.headerNames])
        : RESPONSE_BLOCKED;
      for (const [k, v] of Object.entries(upstream.headers)) {
        // content-length is dropped: we re-stream, so Fastify frames the body.
        if (stripped.has(k) || k === "content-length" || v === undefined) continue;
        // For a `query`-recipe secret, a 3xx Location echoing the request URL
        // would carry the secret in its query string — redact that param.
        reply.header(k, injected.queryParam ? redactQueryParam(k, v, injected.queryParam) : v);
      }
      // The response body is streamed verbatim: an upstream that echoes the
      // secret (or a `?key=…` URL) into the body reaches the app. No header
      // filter closes this — it is an accepted transparent-proxy residual. The
      // dispatcher is shared and long-lived, so the socket returns to the pool
      // when the body drains — never closed per-request (that would defeat the
      // pooling this connector exists to recover).
      // Count the response bytes: a chunked / CL-absent / lying-CL body can't
      // stream past the cap uncounted. Status + headers are already committed,
      // so a trip *truncates* the body (not a 502) — accepted per issue #8; we
      // surface it out-of-band on the log rather than to the app.
      const cappedBody = capBody(upstream.body, deps.limits.maxBodyBytes, "response", () => {
        req.log.warn(
          { origin: instruction.origin, appId: instruction.appId, limit: deps.limits.maxBodyBytes },
          "egress response body exceeded the size cap — truncated",
        );
      });
      return reply.send(cappedBody);
    } catch (err) {
      // The close listener can lose a race to undici rejecting on `abort.signal`; the same
      // writableEnded / requestCapTripped guards apply.
      const disconnected =
        clientGone || (!requestCapTripped && abort.signal.aborted && !reply.raw.writableEnded);
      if (disconnected) {
        // Normal event, not a failure: nothing to write to a dead socket and nothing worth a warn.
        // Outcome stays ok and helix.upstream.status stays 200 — no outcome header was written.
        // helix.client_disconnected (set in proxyHandler's finally) is what separates this path.
        instruments().upstreamAborts.add(1, { [ATTR_CAPABILITY]: instruction.capability });
        return;
      }
      if (requestCapTripped) {
        return fail(reply, 413, "too_large", "request body exceeds the size cap");
      }
      // The connector throws SsrfBlockedError for a blocked/unresolvable host;
      // undici propagates it verbatim, so the old upfront-check semantics hold.
      if (err instanceof SsrfBlockedError) {
        return fail(reply, 403, "blocked", err.message);
      }
      // Everything else — a transport failure, a timeout, or undici refusing a
      // header it considers invalid — reaches the app as an opaque 502, which
      // previously left no trace at all on the one service that can't be debugged
      // by reproducing locally. undici's message names only the offending header
      // *key*, never its value, so logging the error here carries no secret.
      req.log.warn(
        {
          err,
          appId: instruction.appId,
          connection: instruction.connection,
          origin: target.origin,
        },
        "upstream request failed",
      );
      return fail(reply, 502, "upstream_error", "upstream request failed");
    }
  }

  /**
   * The egress span, and the one place in the platform that **extracts** trace
   * context (ADR-0037 decision 7).
   *
   * Extracting here is what makes a `/_api/fetch` call one trace instead of two
   * unjoinable halves in two Log Analytics workspaces — the thing the ADR names
   * as unseeable today. It is sound precisely here and nowhere else: the caller
   * is the edge, over a hop whose authority already comes from the signed
   * attested instruction (ADR-0013). The `traceparent` rides alongside that
   * instruction as correlation only; it is never read for policy, and the
   * verifier does not know it exists.
   *
   * The duration is recorded in the same `finally` as the span end, so the two
   * can never disagree — and both land after the response body has drained,
   * because Fastify's `Reply` is thenable (see `apps/edge/src/telemetry.ts`).
   */
  async function proxyHandler(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const startedAt = performance.now();

    // Authenticate BEFORE deciding the parent. ADR-0037 decision 7 permits
    // extraction here *because* "the caller is the edge, over a hop whose
    // authority already comes from the signed attested instruction" — so that
    // authority has to be established first, or the justification is not true
    // at the line that relies on it. Extracting earlier let anything able to
    // reach `/proxy` choose the parent trace of the resulting span even when
    // the instruction was missing, forged or replayed.
    const auth = await authenticate(req);

    // Parent from the caller only once verified; otherwise a fresh root.
    // Refusals still get a span — a forged instruction or a replayed jti is
    // exactly the thing worth seeing — they are simply not joined to a trace
    // chosen by whoever sent them.
    const parent = auth.ok ? propagation.extract(context.active(), req.headers) : ROOT_CONTEXT;
    const span = tracer.startSpan(
      SPAN_EGRESS_PROXY,
      { kind: SpanKind.SERVER, root: !auth.ok },
      parent,
    );

    let threw = false;
    try {
      if (!auth.ok) return fail(reply, auth.status, auth.code, auth.message);
      return await context.with(trace.setSpan(parent, span), () =>
        runProxy(req, reply, auth.value),
      );
    } catch (err) {
      threw = true;
      // Deliberately NOT `span.recordException(err)`. On this plane an error
      // message can embed credential material — the same reason `app.ts`
      // returns a fixed opaque body and the injection `catch` below binds
      // nothing. A span is a retained backend; the status code is the signal,
      // and the detail stays on the log line that already redacts for it.
      span.setStatus({ code: SpanStatusCode.ERROR });
      throw err;
    } finally {
      // **Nothing below may be read off `reply` on the throw path.** Fastify's
      // error handler (`app.ts`) runs *after* this handler's promise rejects,
      // so at this point an unhandled throw has touched none of it: the outcome
      // header is unset, `statusCode` is still 200, and `writableEnded` is
      // false. Read naively that records "a successful 200 the app hung up on"
      // — a plausible, complete fiction, on the one plane where "the client
      // gave up" and "we broke" send an operator down different paths.
      const outcome = threw ? "error" : String(reply.getHeader(OUTCOME_HEADER) ?? "ok");

      // A refusal returns normally through `fail()`, so the `catch` above never
      // sees it and the span would otherwise end UNSET — including on a 5xx.
      // Grade from what was actually answered. 4xx stays UNSET on purpose: a
      // blocked SSRF target or a replayed jti is this service working.
      if (!threw && reply.statusCode >= 500) {
        span.setStatus({ code: SpanStatusCode.ERROR });
      }

      span.setAttributes(
        egressSpanAttributes({
          [ATTR_OUTCOME]: outcome,
          // Omitted rather than guessed when we threw — the status the caller
          // will actually see is written by the error handler, later.
          [ATTR_UPSTREAM_STATUS]: threw ? undefined : reply.statusCode,
          [ATTR_CLIENT_DISCONNECTED]: !threw && !reply.raw.writableEnded ? true : undefined,
        }),
      );
      instruments().proxyDuration.record(performance.now() - startedAt, {
        [ATTR_OUTCOME]: outcome,
      });
      span.end();
    }
  }

  return { handler: proxyHandler, dispatcher };
}
