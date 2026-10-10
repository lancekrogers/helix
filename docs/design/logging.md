# Logging: levels, correlation, and the `event` convention

What the platform's logs look like today and the rules that keep them useful.
Companion to [ADR-0037](../adr/0037-platform-observability-otlp-boundary.md) —
that ADR covers traces and metrics and **defers the OpenTelemetry log bridge**
(decision 9). Logs stay pino → stdout → the container platform's collector.

## The shape

Every Fastify service uses `loggerOption(nodeEnv, { prefix, mixin })` from
[`packages/shared/src/logging.ts`](../../packages/shared/src/logging.ts).
The shared factory makes log configuration consistent and lets tests verify
that logging stays quiet under NODE_ENV=test.

Lines are `pino.<level>(fields, message)`: an object first, a lowercase human
message second. That is already universal across ~75 call sites; keep it.

## Levels

`<PREFIX>_LOG_LEVEL ?? LOG_LEVEL ?? info`, where `<PREFIX>` is `EDGE`, `PORTAL`
or `EGRESS`. Same two-step fallback the repo uses for `EDGE_PORT ?? PORT`. One
line in `main.bicep` raises the whole platform; one prefixed override raises
only the noisy service.

An unrecognised value **falls back to `info` and says so on stderr; it never
throws.** pino validates the level in its constructor and `Fastify({ logger })`
runs at module scope, so throwing would mean a typo in an env var stops a
service booting. The security seams that *do* boot-fail on a bad value
(`EGRESS_ALLOW_PRIVATE`, the bundle limits) are distinguishable: a wrong value
there silently weakens a control, whereas the worst case here is "logs are at
info, which is what they were yesterday."

> **`debug`/`trace` on the edge is a data-exposure decision, not only a volume
> one.** Anything a `req.log.debug({ body })` writes lands in the retained log
> store. Deliberately not restricted in code — that would disable the knob in
> the exact incident it exists for.

## Correlation

Two identifiers, and they must not be merged:

| Field | What it is | Crosses the hop? |
| --- | --- | --- |
| `reqId` | A UUID minted per request. On the edge → egress hop it rides `x-helix-request-id` and egress adopts it, so both halves of a `/_api/fetch` call share one value across two log stores. | Yes, inward only |
| `trace_id` / `span_id` | The active span, via the `traceContextMixin` pino mixin. Absent unless an OTLP endpoint is configured. | Via `traceparent` |

`reqId` exists **as well as** `trace_id` because the platform's default state is
no exporter configured (ADR-0037 decision 5): a trace-id-only design would give
nothing in a deployment that has not turned telemetry on.

Rules:

- **Never trust an inbound request id on the edge, the portal or the dev
  gateway.** `requestIdHeader` is `false` everywhere; the inbound path lives
  inside `genReqId` so there is one code path and `parseRequestId` is on it.
  Same reasoning as ADR-0037 decision 7 for `traceparent`: unauthenticated
  metadata cannot carry authority.
- **Egress is the one adopter**, and it still shape-validates — a UUID or
  nothing. Its authority comes from the signed instruction, but a forged header
  could still put a newline (forging a log entry) or 8 KB into a retained field.
- **The instruction's `jti`/`requestId` is not a correlation id** and must stay
  a single-use replay nonce (ADR-0037 decision 7 says so explicitly).
- **No call site may log its own `trace_id` or `span_id`** — pino lets an
  explicit field win over the mixin, which would silently shadow them.

## Redacting URLs

Several platform URLs carry a live credential in the query string: the
Appendix A handoff `token`, the OIDC `code`, the consent flow's `state` (the
pending attempt's single-use lookup key) and PKCE `code_verifier`, and —
uncoverable by any name list — the fetch-proxy target's own query, which may
hold an app's API key or an Azure SAS `sig`.

**Log a URL under the top-level key `url`.** `loggerOption` installs a `url`
serializer, so that field is redacted automatically. That is the positive form
of the rule; the negative form ("don't forget `redactUrl`") was an honour system
nobody can keep. An ESLint rule rejects `req.url` / `.href` reaching a log call
unwrapped.

What none of that reaches, stated plainly rather than papered over: a URL
assigned to a variable first, a URL inside an `err.message`, and Fastify's own
two `%s` interpolations. See `TODO.md` (issue #20 residual b).

Span attributes are **stricter**: `spanUrlAttributes` drops the query wholesale
rather than scanning it (ADR-0037 decision 6). A log line's query is
occasionally useful for debugging; a span's never is.

## The `event` convention

`event: "<domain>.<verb>"` — lowercase, snake_case verb, past tense for
outcomes (`load_failed`, not `load_fail`). Introduced by ADR-0025, which needed
a stable field a log-based metric could count because the platform had no
metrics channel.

Registered domains: `boot`, `db`, `registry`, `auth`, `gateway`, `data`,
`egress`, `edge`, `portal`, `secret`, `session`, `otel`, `log`.

Reserved field names, never reused for anything else: `trace_id`, `span_id`,
`reqId`, `err`, `req`, `res`, `url`, `event`, `service`.

### The scoping rule — read this before adding one

**`event` is required only on a line an alert or a dashboard would key on.**

> **Add `event` when you write the alert, not before.**

That is an honest description of what ADR-0025 actually did: it added four
events because it had four signals. Most of the ~75 log lines in this repo do
not want one, and a convention that is 90% ceremony teaches people to ignore it.
There is deliberately no lint rule requiring the field.

Now that ADR-0037's metrics exist, prefer a **metric** for anything you want to
count or threshold, and keep the log line for the detail an operator reads once
the alert fires. Where both exist for one signal they must agree —
`registry.load_failed` and `helix.registry.load_failures` split `failed` vs
`never_loaded` the same way on purpose. Two vocabularies for one signal is the
failure mode.

### Currently in use

| Event | Where |
| --- | --- |
| `boot.serving` | all three services, after `listen` |
| `db.pool_client_error` | every pooled DB client, all services |
| `registry.load_failed` / `registry.never_loaded` / `registry.load_recovered` | `apps/edge/src/registry/listener.ts` |
| `auth.oidc_discovery_ready` / `auth.oidc_discovery_failed` / `auth.code_exchange_failed` | `apps/edge/src/auth/oidc.ts` |
| `auth.oidc_missing_principal` | `apps/edge/src/auth/oidc.ts` — the login refused because the ID token lacks the configured principal claim (ADR-0048 decision 2, as amended; no fallback exists, so this line is the whole diagnosis) |
| `auth.token_missing_principal` | `apps/portal/src/auth/verifier.ts` — the access-token mirror of the same refusal: a correctly signed token with no usable principal claim yields no actor |
| `gateway.usage_record_failed` | the ledger-write failure path — ADR-0021 makes `gateway_calls` the billing and audit authority, so a dropped row matters |
| `edge.unhandled_error` / `portal.unhandled_error` / `egress.unhandled_error` | each service's error handler |
| `secret.destroy_failed` / `secret.audit_write_failed` | `apps/portal/src/routes/secrets.ts` |
| `consent.start_consult_failed` / `consent.start_cross_site_refused` / `consent.cancel_ack_failed` | `apps/edge/src/routing/consentStart.ts`, `consentCancel.ts` — the consent-start route's consult seam failing, a navigation-guard refusal (fail closed), and the helper's cancel-acknowledgement failing (the attempt still expires at the five-minute TTL) |
| `consent.dev_start_consult_failed` | `apps/edge/src/devGateway/consentStart.ts` — the dev-tier handoff's consult failure, mirror of the prod start route's |
| `consent.nonce_entry_failed` | `apps/portal/src/connections/pages.ts` — the dev journey's nonce redemption failing |
| `providers.load_failed` / `providers.load_recovered` / `providers.listen_down` / `providers.row_dropped` | `apps/egress/src/providerListener.ts` — the provider cache's listener lifecycle (ADR-0011); a dropped row is one that failed the shared row parse, so the cache stays fail-closed |
| `exchange.failed` / `exchange.rejected` | `apps/egress/src/exchange.ts` — the code-exchange operation's opaque outcomes; fixed strings only, no vendor response content |
| `egress.renewal.failed` / `egress.renewal.row_unparseable` / `egress.renewal.permissions_lost` / `egress.renewal.uncertain_rotation` / `egress.renewal.seal_failed_after_rotation` | `apps/egress/src/renewal.ts` — the renewal taxonomy's log half (ADR-0007); the last is the rotated-out orphan whose seal failed, which the retirement sweep's ledger re-covers |
| `egress.connection_retire_failed` | `apps/egress/src/retire.ts` — a retirement-sweep destroy failed after its conditional claim; the ledger mark is restored and the pass retries (ADR-0008, criterion 47) |
| `egress.netprobe_check` / `egress.netprobe_result` | `apps/egress/src/netprobe.ts` — the network probe's per-check and summary lines; the failure and absence alerts read the summary |
| `otel.diag` / `otel.config` / `log.level_invalid` | config resolution, written straight to stderr because no logger exists yet |

## What is deliberately not here

- **The OTel log bridge.** ADR-0037 decision 9 defers it until decision 6's
  redaction is demonstrated on that path with tests. The failure mode is a
  retained credential; there is no urgency.
- **A `LOG_EVENTS` constant.** It would make adding a log line a two-file change
  and guard the writer while the reader — an alert rule keying on the string —
  gets nothing.
- **A lint rule requiring `event`.** See the scoping rule.
- **A `hooks.logMethod` message scan.** A per-log-call string scan in the
  trusted path, for a failure mode that needs a double-send bug to reach.
