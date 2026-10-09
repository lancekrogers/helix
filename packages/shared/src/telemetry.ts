/**
 * The telemetry vocabulary — instrument names and attribute keys, as plain
 * strings (ADR-0037 decisions 6 and 8).
 *
 * **This module imports nothing, and must stay that way.** It is the one piece
 * of the observability work that both the edge and egress need to agree on: if
 * the two planes spell `helix.app_id` differently, the trace that crosses the
 * trust boundary is unjoinable and nothing says so — the spans simply never
 * line up. Making the agreement a compile-time one costs a constant.
 *
 * It lives here rather than in `@azx-pbc/telemetry` because that package owns
 * the OpenTelemetry **SDK** and only the `server.ts` files may import it. A
 * string constant has no such constraint, and `@azx-pbc/shared` is already a
 * dependency of every service. Conversely `@opentelemetry/api` must never be
 * added to this package: `packages/cli` (published to npm, ADR-0032) and
 * `apps/portal-web` (a browser bundle) both depend on it, and ADR-0037
 * decision 11 defers browser telemetry precisely to avoid that direction.
 */

/**
 * Instrument names, all `helix.`-prefixed per ADR-0037 decision 8.
 *
 * These are what an alert rule and a dashboard key on, so they are API in the
 * same way `REGISTRY_CHECK_NAME` is — don't rename one without knowing what
 * queries it.
 */
export const INSTR_REGISTRY_STALE_FOR_MS = "helix.registry.stale_for_ms";
export const INSTR_REGISTRY_LOAD_FAILURES = "helix.registry.load_failures";
export const INSTR_GATEWAY_CALLS = "helix.gateway.calls";
export const INSTR_GATEWAY_DURATION = "helix.gateway.duration";
export const INSTR_EGRESS_PROXY_DURATION = "helix.egress.proxy.duration";
export const INSTR_SESSION_GATE_DENIED = "helix.session.gate_denied";
export const INSTR_TRUST_PROXY_UNRESOLVED = "helix.edge.trust_proxy.unresolved";
export const INSTR_PROVIDERS_RECONCILES = "helix.providers.reconciles";
export const INSTR_PROVIDERS_LISTEN_STATUS = "helix.providers.listen_status";
export const INSTR_CONSENT_OPERATIONS = "helix.consent.operations";
export const INSTR_EGRESS_EXCHANGES = "helix.egress.exchanges";
export const INSTR_EGRESS_RENEWALS = "helix.egress.renewals";
export const INSTR_EGRESS_RETIREMENTS = "helix.egress.retirements";
export const INSTR_EGRESS_UPSTREAM_ABORTS = "helix.egress.upstream_aborts";
export const INSTR_APP_VISITS = "helix.app.visits";
export const INSTR_GATEWAY_CUT_CHARGES = "helix.gateway.cut_charges";
export const INSTR_GATEWAY_ADMISSION_DENIED = "helix.gateway.admission_denied";
export const INSTR_GATEWAY_PLATFORM_SPEND_RATIO = "helix.gateway.platform_spend_ratio";

/**
 * Attribute keys.
 *
 * `helix.`-prefixed rather than reusing OpenTelemetry semantic conventions,
 * because none of these are semconv attributes and squatting on a semconv name
 * with our own meaning is worse than inventing one. The two genuine semconv
 * keys we do use — `url.path` and `http.route` — are spelled out at their call
 * sites; see {@link FORBIDDEN_URL_ATTRS} for the ones that are banned.
 */
export const ATTR_APP_ID = "helix.app_id";
export const ATTR_ENV = "helix.env";
export const ATTR_CAPABILITY = "helix.capability";
export const ATTR_OUTCOME = "helix.outcome";
export const ATTR_REASON = "helix.reason";
export const ATTR_MODEL = "helix.model";
export const ATTR_METHOD = "helix.method";
export const ATTR_TARGET_ORIGIN = "helix.target.origin";
export const ATTR_TARGET_PATH = "helix.target.path";
export const ATTR_CONNECTION = "helix.connection";
export const ATTR_UPSTREAM_STATUS = "helix.upstream.status";
export const ATTR_CLIENT_DISCONNECTED = "helix.client_disconnected";
export const ATTR_USAGE_BASIS = "helix.usage.basis";
/**
 * How egress sourced the injected credential — `secret` (a sealed `app_secrets`
 * row), `managed-identity` (a minted Entra token, ADR-0046), or `delegated`
 * (the caller's own OAuth connection). Bounded to those three
 * values; never the credential itself, its header name, or a token claim.
 */
export const ATTR_CREDENTIAL_SOURCE = "helix.credential_source";
export const ATTR_STREAM = "helix.stream";
/**
 * The app's slug. Bounded by the tenant like {@link ATTR_APP_ID}, and the half
 * a human recognises — kept as a SPAN attribute only. `appId` remains the
 * metric dimension, because a slug can be reused after an app is deleted while
 * the uuid cannot, and a metric series that silently changes meaning is worse
 * than one that is hard to read.
 */
export const ATTR_APP_SLUG = "helix.app.slug";
/** Which app-data verb — `putUser`, `getShared`, … Bounded by the handler set. */
export const ATTR_DATA_VERB = "helix.data.verb";
/**
 * How many keys a `shared` list call matched (ADR-0042 decision 7). Bounded by
 * the page cap, and deliberately the COUNT — the matched keys themselves are
 * app data and never ride a span.
 */
export const ATTR_DATA_MATCH_COUNT = "helix.data.match_count";
/** How many apps the registry projection loaded. Bounded by the tenant. */
export const ATTR_REGISTRY_APPS = "helix.registry.apps";
/**
 * How many provider rows the egress cache holds after a reconcile. Bounded by
 * the tenant — the table is administrator-created.
 */
export const ATTR_PROVIDERS = "helix.providers.rows";
/** Files in a deployed bundle, and CSP lint warnings raised on it. */
export const ATTR_DEPLOY_FILE_COUNT = "helix.deploy.file_count";
export const ATTR_DEPLOY_WARNING_COUNT = "helix.deploy.warning_count";
/**
 * Which consent-flow operation a signal is about — `consult`, `cancel`,
 * `claim`, `sweep`, `redeem`, `callback`, or `status` (`redeem`
 * is the dev journey's nonce redemption; `callback` is the completion
 * state machine the vendor redirect lands in; `status` is the
 * read-only connection-status read, ADR-0031 as amended). Bounded to those
 * seven; the identity the operation is for is never a dimension.
 */
export const ATTR_CONSENT_OPERATION = "helix.consent.operation";
/** The provider `ref` a consent operation consults against — admin-chosen, ≤64 chars. */
export const ATTR_PROVIDER_REF = "helix.provider_ref";
/** How many expired consent-attempt rows a sweep cycle removed. */
export const ATTR_CONSENT_SWEEP_REMOVED = "helix.consent.sweep_removed";
/** How many pending consent attempts a disconnect killed. */
export const ATTR_ATTEMPTS_KILLED = "helix.attempts_killed";

/**
 * Span names. Like the instrument names these are queried by humans and by
 * dashboards, so they are constants rather than string literals at the call
 * site — a typo in one of ~14 hand-placed spans is otherwise invisible until
 * someone notices a trace view is missing a step.
 */
export const SPAN_LLM = "helix.gateway.llm";
export const SPAN_FETCH = "helix.gateway.fetch";
export const SPAN_DATA = "helix.gateway.data";
export const SPAN_EGRESS_PROXY = "helix.egress.proxy";
export const SPAN_EGRESS_RESOLUTION = "helix.egress.resolution";
export const SPAN_EGRESS_EXCHANGE = "helix.egress.exchange";
export const SPAN_EGRESS_RENEWAL = "helix.egress.renewal";
export const SPAN_EGRESS_RETIRE = "helix.egress.retire";
export const SPAN_REGISTRY_LOAD = "helix.registry.load";
export const SPAN_PROVIDERS_RECONCILE = "helix.providers.reconcile";
export const SPAN_AUTH_START = "helix.auth.oidc.start";
export const SPAN_AUTH_CALLBACK = "helix.auth.oidc.callback";
export const SPAN_AUTH_COMPLETE = "helix.auth.handoff.complete";
export const SPAN_CONNECTIONS_PROXY = "helix.auth.connections.proxy";
export const SPAN_DEPLOY_BUNDLE = "helix.deploy.bundle";
export const SPAN_DEPLOY_VALIDATE = "helix.deploy.validate";
export const SPAN_DEPLOY_ALLOCATE = "helix.deploy.allocate";
export const SPAN_DEPLOY_UPLOAD = "helix.deploy.upload";
export const SPAN_DEPLOY_RECORD = "helix.deploy.record";
export const SPAN_CONSENT_CONSULT = "helix.consent.consult";
export const SPAN_CONSENT_CANCEL = "helix.consent.cancel";
export const SPAN_CONSENT_CLAIM = "helix.consent.claim";
export const SPAN_CONSENT_SWEEP = "helix.consent.sweep";
export const SPAN_CONSENT_CALLBACK = "helix.consent.callback";
export const SPAN_CONSENT_START = "helix.consent.start";
export const SPAN_CONSENT_START_DEV = "helix.consent.start.dev";
export const SPAN_CONSENT_REDEEM = "helix.consent.redeem";
/** The app-facing connection-status read (ADR-0031 as amended) — the portal's
 * read-only decision behind the edge's `.status.edge` / `.status.dev` routes. */
export const SPAN_CONSENT_STATUS = "helix.consent.status";
/** The prod edge route `GET /_api/connections/:ref/status`, which forwards to
 * the portal's own `.status` span over the internal seam. */
export const SPAN_CONSENT_STATUS_EDGE = "helix.consent.status.edge";
/** The dev gateway's `GET /:slug/_api/connections/:ref/status`. */
export const SPAN_CONSENT_STATUS_DEV = "helix.consent.status.dev";
/** The edge's app-facing cancel-acknowledgement route, which
 * forwards to the portal's own cancel span (above) over the internal seam. */
export const SPAN_CONSENT_CANCEL_EDGE = "helix.consent.cancel.edge";
/** The portal's My Connections list route — the caller's own
 * connections, metadata only. */
export const SPAN_CONNECTIONS_MINE = "helix.connections.mine";
/** The portal's disconnect route — the one-transaction
 * invalidation that stops the caller's own Helix access. */
export const SPAN_CONNECTIONS_DISCONNECT = "helix.connections.disconnect";

/**
 * `http.route` values. The literal route pattern, never the request URL —
 * ADR-0037 decision 6 forbids `url.full`/`http.url`, and on these routes there
 * is nothing variable to record anyway.
 */
export const ROUTE_LLM = "/_api/llm/chat";
export const ROUTE_OPENAI = "/_api/openai/v1/chat/completions";
export const ROUTE_FETCH = "/_api/fetch/*";
export const ROUTE_DATA = "/_api/data/*";
export const ROUTE_AUTH_START = "/start";
export const ROUTE_AUTH_CALLBACK = "/callback";
export const ROUTE_AUTH_COMPLETE = "/_auth/complete";
export const ROUTE_CONNECTIONS = "/connections/*";
export const ROUTE_CONSENT_START = "/_api/connections/:ref/start";
export const ROUTE_CONSENT_START_DEV = "/:slug/_api/connections/:ref/start";
export const ROUTE_CONSENT_STATUS = "/_api/connections/:ref/status";
export const ROUTE_CONSENT_STATUS_DEV = "/:slug/_api/connections/:ref/status";
export const ROUTE_CONSENT_CANCEL = "/_api/connections/attempt/cancel";
export const ROUTE_CONNECTIONS_NONCE_ENTRY = "/connections/consent/start";
export const ROUTE_CONNECTIONS_CALLBACK = "/connections/callback";
export const ROUTE_CONNECTIONS_MINE = "/api/v1/connections/mine";
export const ROUTE_CONNECTIONS_MINE_ID = "/api/v1/connections/mine/:id";
export const ROUTE_EGRESS_EXCHANGE = "/exchange";

/**
 * Attribute keys that must never appear on a span, anywhere (ADR-0037
 * decision 6).
 *
 * Several platform URLs carry a live credential in the query string: the
 * Appendix A handoff `token`, the OIDC `code`, and — uncoverable by any name
 * list — the fetch-proxy target's own query, which may hold an app's API key or
 * an Azure SAS `sig`. These are exactly the semantic-convention keys that
 * carry a full URL, and a span attribute lands in a 30-day-retained backend
 * the same way a log line does.
 *
 * Record `url.path` and `http.route` instead, and put anything URL-shaped
 * through `redactUrl` from `@azx-pbc/shared/logging` first. An ESLint rule
 * enforces this list; the constant is here so the rule and the docs cannot
 * drift from each other.
 */
export const FORBIDDEN_URL_ATTRS = ["url.full", "http.url", "http.target", "url.query"] as const;

/**
 * Why a session-gate denial happened — the `helix.session.gate_denied`
 * dimension.
 *
 * Bounded by construction: these are the early returns in
 * `apps/edge/src/auth/gate.ts`, and a test asserts the set is exhaustive. The
 * *response* stays indistinguishable across all of them (`apps/edge/src/errors.ts`
 * exists so a guard doesn't disclose which one fired) — this records the reason
 * internally without changing a byte of what the caller sees.
 */
export const SESSION_DENIAL_REASONS = [
  "mode_forbidden",
  "no_session",
  "visibility_denied",
  "refresh_required",
] as const;
export type SessionDenialReason = (typeof SESSION_DENIAL_REASONS)[number];

/**
 * Why the LLM gateway refused a call before sending it upstream: the `helix.reason`
 * dimension of `helix.gateway.admission_denied`. Bounded by construction: these are the
 * refusal branches in `apps/edge/src/gateway/llm.ts`, and a test asserts the set.
 * `app_budget_day` and `app_budget_burst` are the per-app USD windows.
 */
export const ADMISSION_DENIAL_REASONS = [
  "app_budget_day",
  "app_budget_burst",
  "platform_ceiling",
  "concurrency_app",
  "concurrency_user",
  "concurrency_replica",
] as const;
export type AdmissionDenialReason = (typeof ADMISSION_DENIAL_REASONS)[number];

/**
 * Why a registry projection load failed — the `helix.registry.load_failures`
 * dimension. Mirrors the split `apps/edge/src/registry/listener.ts` already
 * makes between its two event names, so the counter and the log agree.
 */
export const REGISTRY_LOAD_OUTCOMES = ["failed", "never_loaded"] as const;
export type RegistryLoadOutcome = (typeof REGISTRY_LOAD_OUTCOMES)[number];

/**
 * What happened to a visit the edge decided to record — the `helix.app.visits`
 * dimension (ADR-0050). The row is written fire-and-forget, so this counter is
 * the only place a lost visit is visible.
 *
 * - `recorded`: the row landed.
 * - `failed`: the write was attempted and errored (including a pool wait that
 *   timed out).
 * - `dropped`: too many writes were already in flight, so none was attempted.
 *   A sustained rate means the database is slow or someone is flooding loads.
 * - `deduplicated`: the same visitor was recorded on this replica within the
 *   last minute, so the row would add nothing to the 30-minute visit grouping.
 */
export const VISIT_RECORD_OUTCOMES = ["recorded", "failed", "dropped", "deduplicated"] as const;
export type VisitRecordOutcome = (typeof VISIT_RECORD_OUTCOMES)[number];

/**
 * Why a provider-cache reconcile was counted — the `helix.providers.reconciles`
 * dimension. An attempt counter, not a failures-only counter: the cache has no
 * `/health` grade to ladder into (egress reports liveness only), so the alert
 * is a *rate* — a run of `failed` with no `ok` is a stale-config cache.
 */
export const PROVIDERS_RECONCILE_OUTCOMES = ["ok", "failed"] as const;
export type ProvidersReconcileOutcome = (typeof PROVIDERS_RECONCILE_OUTCOMES)[number];

/**
 * How a cut or failed LLM call's charge was derived: the `helix.usage.basis` span
 * attribute and the `helix.gateway.cut_charges` dimension. `measured`: both counts
 * came from the vendor's usage block. `estimated`: both came from byte counts.
 * `mixed`: one of each (for example a measured input and an estimated output).
 */
export const CUT_CHARGE_BASES = ["measured", "estimated", "mixed"] as const;
export type CutChargeBasis = (typeof CUT_CHARGE_BASES)[number];

/**
 * Why a `shared` list call was denied — the {@link ATTR_REASON} value on the
 * `helix.gateway.data` span, separating the deny path from an empty result
 * (ADR-0042 decision 7). Bounded by construction: these are the authorization
 * early-returns in `listShared` (`apps/edge/src/gateway/data-handler.ts`), and
 * the *response* stays an ordinary 403 — this records the reason internally,
 * like {@link SESSION_DENIAL_REASONS}, without changing a byte the caller sees.
 */
export const DATA_LIST_DENIAL_REASONS = ["prefix_not_granted"] as const;
export type DataListDenialReason = (typeof DATA_LIST_DENIAL_REASONS)[number];

/**
 * Outcome vocabularies for the consent-flow operations, the
 * `helix.outcome` values on the `helix.consent.operations` counter and the
 * operation spans. Bounded by construction — each list is exactly the early
 * returns of its operation in `apps/portal/src/connections/consent.ts` — and
 * deliberately free of identity: `userOid` is never a dimension.
 *
 * - consult: `started` (pending attempt written + authorize URL returned),
 *   `already_connected`, `not_available`, `error` (custody/DB failure — the
 *   edge's "couldn't start").
 * - cancel: `cancelled` (owner won the CAS), `not_cancellable` (unknown,
 *   expired, finished, or not the caller's attempt — indistinguishable on the
 *   wire), `error`.
 * - claim: `claimed` (single-use redeem won), or the refusal reason the
 *   callback renders — `expired`, `cancelled`, `not_found` — plus `error`.
 * - sweep: `ok` (cycle ran; the removed count rides the span) or `failed`.
 */
export const CONSENT_OPERATIONS = [
  "consult",
  "cancel",
  "claim",
  "sweep",
  "redeem",
  "callback",
  "status",
] as const;
export type ConsentOperation = (typeof CONSENT_OPERATIONS)[number];
export const CONSENT_CONSULT_OUTCOMES_TELEMETRY = [
  "started",
  "already_connected",
  "not_available",
  "error",
] as const;
export const CONSENT_CANCEL_OUTCOMES_TELEMETRY = ["cancelled", "not_cancellable", "error"] as const;
export const CONSENT_CLAIM_OUTCOMES_TELEMETRY = [
  "claimed",
  "expired",
  "cancelled",
  "not_found",
  "error",
] as const;
export const CONSENT_SWEEP_OUTCOMES_TELEMETRY = ["ok", "failed"] as const;
export const CONSENT_REDEEM_OUTCOMES_TELEMETRY = [
  "redeemed",
  "not_found",
  "replayed",
  "expired",
  "cancelled",
  "provider_changed",
  "error",
] as const;

/**
 * Why the connect callback answered as it did — the
 * `helix.outcome` values on the `helix.consent.callback` span and the
 * `helix.consent.operations` counter's `callback` operation. This is the
 * ten-word vocabulary, verbatim: the terminal
 * outcomes the callback's completion pages render.
 *
 * - `connected` — the exchange succeeded and the row saved (CAS winner).
 * - `already_connected` — in the vocabulary for the design's completeness; the
 *   callback's CAS maps a live-row race to `conflict` (a
 *   competing attempt reports a conflict, never silent replacement), so today
 *   no path emits this word.
 * - `denied` — the vendor returned an OAuth error (the declined page), or the
 *   `state` claimed nothing (forged, reused, cross-context — unknown states
 *   render the fixed refusal page; there is no not-found word to emit).
 * - `expired` / `cancelled` / `disconnected` — the attempt refused or the
 *   connection row's state says this attempt can no longer establish anything.
 * - `failed_permissions` / `failed_provider` / `failed_service` — the egress
 *   exchange's rejections (`missing_permissions`), provider unavailability and
 *   gate rejections, and transport/service failure respectively.
 */
export const CONSENT_CALLBACK_OUTCOMES = [
  "connected",
  "already_connected",
  "denied",
  "expired",
  "conflict",
  "cancelled",
  "disconnected",
  "failed_permissions",
  "failed_provider",
  "failed_service",
] as const;
export type ConsentCallbackOutcome = (typeof CONSENT_CALLBACK_OUTCOMES)[number];

/**
 * Why the edge's consent-start route answered as it did — the
 * `helix.outcome` values on the `helix.consent.start` span. Distinct from the
 * consult vocabulary above because the edge decides things the consult never
 * sees: `signin_required` (no usable session — detected before any consult is
 * made) and `forbidden` (the same-origin navigation guard refused). The
 * consult's own outcomes map onto `started` / `already_connected` /
 * `unavailable` (`not_available`), and every failure path — portal hop,
 * unconfigured seam, malformed response — is `error`.
 */
export const CONSENT_START_OUTCOMES = [
  "started",
  "signin_required",
  "already_connected",
  "unavailable",
  "forbidden",
  "error",
] as const;
export type ConsentStartOutcome = (typeof CONSENT_START_OUTCOMES)[number];

/**
 * The dev-tier start route's outcome vocabulary — the
 * `helix.outcome` values on the `helix.consent.start.dev` span. The prod
 * vocabulary minus `signin_required`: a dev caller's identity is the bearer
 * token, not a session, so there is no sign-in state — the resolver's
 * refusals (missing/invalid token, wrong app, unregistered Origin, refused
 * before any consult) are `forbidden`.
 */
export const CONSENT_START_DEV_OUTCOMES = [
  "started",
  "already_connected",
  "unavailable",
  "forbidden",
  "error",
] as const;
export type ConsentStartDevOutcome = (typeof CONSENT_START_DEV_OUTCOMES)[number];

/**
 * Why the app-facing connection-status read answered as it did (ADR-0031 as
 * amended) — the `helix.outcome` values on the `helix.consent.status` /
 * `.status.edge` spans. The three row-state words pass through from the
 * portal's decision (`connected`, `not_connected`, `not_available` — the same
 * collapse the delegated-call error table makes); the edge adds `unauthorized`
 * (no usable session — a pseudonym or an anonymous visitor is refused the same
 * way) and `error` (portal hop failure or an unconfigured seam).
 */
export const CONSENT_STATUS_OUTCOMES = [
  "connected",
  "not_connected",
  "not_available",
  "unavailable",
  "unauthorized",
  "error",
] as const;
export type ConsentStatusOutcome = (typeof CONSENT_STATUS_OUTCOMES)[number];

/**
 * The dev-tier status route's outcome vocabulary — the prod set with
 * `forbidden` in place of `unauthorized`: a dev caller's identity is the
 * bearer token, and the dev resolver's refusals (missing/invalid token, wrong
 * app, unregistered Origin) are `forbidden` (the dev start route's posture).
 */
export const CONSENT_STATUS_DEV_OUTCOMES = [
  "connected",
  "not_connected",
  "not_available",
  "unavailable",
  "forbidden",
  "error",
] as const;
export type ConsentStatusDevOutcome = (typeof CONSENT_STATUS_DEV_OUTCOMES)[number];

/**
 * Why the edge's cancel-acknowledgement route answered as it did
 * — the `helix.outcome` values on the `helix.consent.cancel.edge` span. The
 * forwarded call's own outcomes (`cancelled`/`not_cancellable`) pass through;
 * the edge adds what only it decides: `unauthorized` (no usable session or a
 * cross-origin POST — the caller learns nothing either way) and
 * `unknown_attempt` (no live tag correlation on this replica — the helper's
 * acknowledgement then degrades to the attempt's five-minute expiry, the bound
 * the design already documents; the response body stays the indistinguishable
 * `not_cancellable`).
 */
export const CONSENT_CANCEL_EDGE_OUTCOMES = [
  "cancelled",
  "not_cancellable",
  "unknown_attempt",
  "unauthorized",
  "error",
] as const;
export type ConsentCancelEdgeOutcome = (typeof CONSENT_CANCEL_EDGE_OUTCOMES)[number];

/**
 * The egress code-exchange operation's outcome vocabulary —
 * the `helix.outcome` dimension on `helix.egress.exchanges` and
 * the `helix.egress.exchange` span. Bounded by construction: each value is
 * exactly one early-return class of the handler.
 *
 * - `exchanged` — the compatibility gate passed and both materials sealed.
 * - `rejected` — the gate refused at receipt (the distinguishable reason rides
 *   the span's `helix.reason`, never a metric dimension); nothing was sealed.
 * - `provider_unavailable` — unknown id, deleted, or stale revision.
 * - `exchange_failed` — the vendor token endpoint failed or sealing failed;
 *   the fixed-string outcome, no vendor content anywhere.
 * - `unauthorized` — the portal→egress token did not verify (refused before
 *   any vendor call).
 * - `malformed` — the body failed its schema parse.
 * - `unconfigured` — the exchange operation has no custody/providers wired.
 */
export const EGRESS_EXCHANGE_OUTCOMES = [
  "exchanged",
  "rejected",
  "provider_unavailable",
  "exchange_failed",
  "unauthorized",
  "malformed",
  "unconfigured",
] as const;
export type EgressExchangeOutcome = (typeof EGRESS_EXCHANGE_OUTCOMES)[number];

/**
 * The egress token-renewal operation's outcome vocabulary —
 * the `helix.outcome` values on the `helix.egress.renewal` span
 * and the `helix.egress.renewals` counter. This is the
 * operator-visible renewal vocabulary, verbatim; the delegated-call
 * resolver maps each word onto the gateway outcome the caller sees.
 *
 * - `refreshed` — fresh usable material is committed (renewed here, or a
 *   concurrent winner's renewal re-read after the advisory lock — ADR-0031
 *   decision 15).
 * - `temporary_failure` — vendor outage, rate limit, or a timeout with no
 *   certain token consumption; the connection row is untouched and a later
 *   request may try again. No vendor retry within the call.
 * - `uncertain_rotation` — the refresh token may have been consumed with no
 *   usable replacement saved; the row moves to reconnect-needed and the old
 *   token is never re-presented. Takes precedence over
 *   `temporary_failure`.
 * - `reconnect_required` — an explicit loss of required permissions; the row
 *   moves to reconnect-needed.
 * - `admin_action` — malformed client credentials or a missing usable
 *   lifetime; provider incompatibility an administrator must fix. The row is
 *   untouched (the connection is not the problem).
 */
export const EGRESS_RENEWAL_OUTCOMES = [
  "refreshed",
  "temporary_failure",
  "uncertain_rotation",
  "reconnect_required",
  "admin_action",
] as const;
export type EgressRenewalOutcome = (typeof EGRESS_RENEWAL_OUTCOMES)[number];

/**
 * The egress delegated-resolution operation's outcome vocabulary
 * — the `helix.outcome` values on the `helix.egress.resolution` span, the span
 * the proxy opens around resolving one delegated instruction's connection.
 * These are the operator-visible signals; how each word
 * answers the caller is the delegated-call error table:
 *
 * - `resolved` — a usable access token came off the row directly; the call
 *   dispatches.
 * - `refreshed` — the token was expired (or the renew-before-next-call flag
 *   was set), the
 *   renewal succeeded, and the call dispatches on the fresh token, invisible
 *   to the caller. The renewal span inside this one carries the
 *   same word.
 * - `connection_required` — no or dead connection, a caller kind that can
 *   never hold one, or a renewal that ended `uncertain_rotation` /
 *   `reconnect_required` — the caller must Connect (403).
 * - `reconnect_required` — the connection row itself is live but renewal said
 *   reconnection is required and the row has been flipped; emitted beside
 *   `connection_required`'s answer when the distinction matters on the span.
 *   (The app-facing answer is still `connection_required`.)
 * - `provider_unavailable` — the provider was deleted, or the row's revision
 *   stamp is behind the cached current one —
 *   503.
 * - `provider_misconfigured` — the provider row is malformed or its renewal
 *   answered `admin_action` — administrator action required (502).
 * - `error` — resolution could not complete: a temporary renewal failure
 *   (the state diagram's UpstreamError arm; the renewal span inside carries
 *   the specific `temporary_failure` word) or a custody/infrastructure
 *   failure. The app-facing answer is the existing 502 `upstream_error`.
 */
export const EGRESS_RESOLUTION_OUTCOMES = [
  "resolved",
  "refreshed",
  "connection_required",
  "reconnect_required",
  "provider_unavailable",
  "provider_misconfigured",
  "error",
] as const;
export type EgressResolutionOutcome = (typeof EGRESS_RESOLUTION_OUTCOMES)[number];

/**
 * What the egress credential-retirement sweep did with one ledger entry
 * (ADR-0031 amendment item 12) — the `helix.outcome` dimension on
 * `helix.egress.retirements`. Bounded by construction — each value is one
 * branch of the sweep's per-entry flow.
 *
 * - `retired` — the conditional claim won and the claimed material was
 *   destroyed; the row's ledger field is clear.
 * - `failed` — the claim won but the destroy did not succeed; the entry is
 *   restored to the ledger and retried on a later pass, and
 *   the fixed `egress.connection_retire_failed` warn event rides alongside.
 * - `claimed_lost` — the conditional claim matched zero rows: a writer
 *   (a reconnect's swap, a renewal's rotation, a newer mark) re-purposed the
 *   single-slot ledger between the sweep's read and its claim, so the sweep
 *   destroyed nothing (a current connection's material is
 *   never touched). Losing is the design working; it is counted, not alarmed.
 */
export const EGRESS_RETIREMENT_OUTCOMES = ["retired", "failed", "claimed_lost"] as const;
export type EgressRetirementOutcome = (typeof EGRESS_RETIREMENT_OUTCOMES)[number];

/**
 * The retirement sweep's pass-level outcome (the `helix.egress.retire` span) —
 * whether the pass could run at all. Per-entry results ride the
 * `helix.egress.retirements` counter, not this span; a pass full of failed
 * destroys still ran.
 */
export const EGRESS_RETIRE_PASS_OUTCOMES = ["ok", "failed"] as const;
export type EgressRetirePassOutcome = (typeof EGRESS_RETIRE_PASS_OUTCOMES)[number];

/**
 * Duration buckets in milliseconds. LLM streams often exceed OTel's default
 * 10-second upper bucket, so extend the range to measure tail latency.
 */
/**
 * Maximum recorded target-path length before the ellipsis. Match the
 * gateway_calls.path cap on both edge and egress.
 *
 * This bounds attacker-controlled retained data; it does not redact secrets
 * embedded in path segments. See fetchPathOf in apps/edge/src/gateway/usage.ts.
 */
export const TARGET_PATH_MAX = 512;

/**
 * Apply {@link TARGET_PATH_MAX}. Kept here rather than in either plane so the
 * one definition is reachable from both — this module imports nothing, which is
 * what lets egress use it without reaching into `apps/edge`.
 */
export function capTargetPath(pathname: string): string {
  return pathname.length > TARGET_PATH_MAX ? `${pathname.slice(0, TARGET_PATH_MAX)}…` : pathname;
}

export const DURATION_BUCKETS_MS = [
  0, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000, 120_000,
] as const;
