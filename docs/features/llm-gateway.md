# LLM gateway

> **Related ADRs:** [ADR-0008](../adr/0008-llm-key-via-egress.md) (LLM key via egress) · [ADR-0021](../adr/0021-metering-ledger.md) (metering ledger) · [ADR-0014](../adr/0014-same-origin-api-gateway.md) (same-origin API gateway) · [ADR-0033](../adr/0033-openai-compatible-gateway-surface.md) (OpenAI-compatible surface + multi-provider routing) · [ADR-0034](../adr/0034-structured-output-on-the-llm-gateway.md) (structured output).

`POST /_api/llm/chat` sends a language-model request through the platform.
The edge resolves the caller, checks the request origin and app's model allowlist,
enforces its daily budget, and records usage. Egress supplies the vendor
credential and makes the outbound call. The vendor-neutral request and response
schemas are in `packages/shared/src/llm.ts` (architecture §6.1, project plan §4 M4).

Handler: `apps/edge/src/gateway/llm.ts` (`makeLlmHandler`). Route wiring:
`apps/edge/src/app.ts` (`POST /_api/llm/chat`). App hosts only — `sendNotFound` elsewhere.

## How it works

### The preamble (same shape as app-data)

1. **Resolve serving entry** — `resolveServingEntry(registry, slug)`; archived/missing → handled.
2. **Resolve caller** — the `CallerResolver` from [authentication.md](./authentication.md). A
   fetch with no/expired session gets the gate's 401 (or `refresh_required`); on a `public` app
   the gate is **skipped entirely** (public apps route around the auth host) and the caller is
   anonymous (`ANON_USER_OID`). An anonymous caller has no per-user budget, so on public apps a
   per-IP fixed-window limiter runs here, ahead of everything else (`anonRateLimited` →
   `429 rate_limited`, not metered).
3. **CSRF** — `isSameOrigin(req.headers.origin, …)`; a sibling subdomain must not POST on the
   user's session (SameSite doesn't cover cross-subdomain — Origin does). Mismatch → `403`.
4. **Capability configured?** — if no vendor key/usage ledger on this edge → `503`
   `capability_unavailable`.
5. **Validate body** — `LlmChatRequestSchema.safeParse`; bad → `400`.
6. **Authz** — the app must hold an `llm` grant (`entry.llm`) and the requested `model` must be
   in `entry.llm.models` (else `403 forbidden` / `403 model_not_allowed`).

### Quota (block-new, finish-in-flight)

The budget is checked **once at admission** against the frozen `costMicroUsd` ledger column,
over two windows: the calendar day (`429 quota_exceeded`) and a rolling hour at a fraction of
it (`429 rate_limited`, the burst/availability control, so one actor can't drain the day in a
spike). Either way a `quota_blocked` row is recorded, throttled per app and env (20 per minute
per replica) so a flood of refusals cannot become a ledger write flood; the
`helix.gateway.admission_denied` counter still counts every refusal. The effective daily cap is
`entry.llm.dollarsPerDay` when set, otherwise `EDGE_LLM_DEFAULT_DOLLARS_PER_DAY` (default
$50/day, matching the approval baseline). Setting that install knob to `0` makes an unset
manifest budget unlimited again. An admitted request always runs to completion even if it tips
the app over — the **next** request is the one that gets blocked
(`apps/edge/src/gateway/llm.ts`). The alternative (cutting an in-flight stream at the byte that
crosses the line) buys nothing — the tokens are already spent upstream — and would corrupt the
response mid-sentence. Block-new keeps the budget a coarse daily ceiling, not a hard per-token
cap, and the blocked call **is** audited (a `quota_blocked` row, distinct from the calls that
record nothing — see below). The approval classifier cannot see
`EDGE_LLM_DEFAULT_DOLLARS_PER_DAY`, so removing an explicit LLM cap is elevated even though the
edge will enforce the install default — that default may be above the $50 baseline or unlimited
(`0`). See [capabilities-and-manifests.md](./capabilities-and-manifests.md) for the full rules.

When `EDGE_LLM_PLATFORM_DOLLARS_PER_DAY` is positive, the edge also refuses new LLM calls
platform-wide once the day's summed `costMicroUsd` across all apps reaches that ceiling
(`503 capability_unavailable`, message "platform LLM budget exhausted for today"), with
`retry-after` set to seconds until the next local midnight (the same `date_trunc('day', now())`
window as the per-app gate). The check runs after the per-app gate so an app over its own
budget still gets `429`. Denials record `quota_blocked` with `errorDetail = platform_ceiling`,
throttled like other quota refusals, and increment `helix.gateway.admission_denied` with reason
`platform_ceiling`. Spend is read through a `SECURITY DEFINER` aggregate, cached per edge
replica for five seconds — overshoot is at most the ceiling plus calls admitted before the
cache catches up. A failed read fails closed (`503`, `retry-after: 5`). `0` or unset disables
the ceiling locally; deployed installs receive a Bicep-derived default.

### Provider seam + streaming

`apps/edge/src/gateway/provider.ts` defines a vendor-agnostic `LlmProvider`:
`stream(req, {signal, appId, userOid, requestId}) → AsyncIterable<LlmStreamEvent>`, where events
are `{type: "delta", text}`, optional interim `{type: "usage", usage}` events as the vendor
reports token counts, then a final `{type: "done", stopReason, usage}`. It is a deliberate
**seam, not a cloned vendor API namespace** — the app speaks the platform's own
`packages/shared/src/llm.ts` wire contract, and the gateway translates. That indirection is what
keeps the key out of reach: there is no edge surface that echoes the upstream request, so the app
**never sees the vendor key** and can't smuggle raw vendor parameters past the manifest allowlist.
The implementation is **Anthropic**, streamed over undici (no SDK — the edge stays
dependency-minimal, project plan §1), always requesting `stream: true` upstream and parsing SSE.

**Where the vendor key lives.** The default provider, `EgressLlmProvider`
(`apps/edge/src/gateway/egressLlmProvider.ts`), does **not** hold the key: the key is a
`platform`-scoped secret (named by `EDGE_LLM_ANTHROPIC_CONNECTION`, default `anthropic`) managed
in the portal Secrets admin page and resolved by `helix-egress`. The edge keeps all the policy
above; it only mints an attested `llm` instruction and forwards the call over the `EgressProvider`
seam — egress injects `x-api-key` and streams the SSE back, which the edge parses for usage and
metering (shared `mapAnthropicStream`). This is the same policy/mechanism split as the fetch-proxy,
and it removes the one spot where the edge held plaintext (secrets design §1). Rotating the key in
the portal takes effect on the next call with no edge restart. There is **no direct edge→Anthropic
path**: when egress is unconfigured the capability fails **closed** — `/_api/llm/chat` returns
`503 capability_unavailable`, the edge never holds the vendor key (issue #10, ADR-0008). The
`AnthropicProvider` class survives as a test-only unit (constructor-injected key); it is never
selected at runtime.

The handler relays this two ways:

- **Streaming** (`chat.stream`, the default) — hijacks the reply and writes
  `text/event-stream` with `x-accel-buffering: no` (defeats proxy buffering). Emits
  `event: delta` records as text arrives, then `event: done` with `{stopReason, usage}`; on
  failure, `event: error` `{code, message}`.
- **Non-streaming** — accumulates deltas into a single `LlmChatResponseSchema` JSON body;
  upstream failures become `502` — except an upstream `429`, which passes through as
  `429 rate_limited` (with `retry-after` when the vendor sent one, else a fixed 5s) so the app's
  SDK retry/backoff engages instead of reading a platform outage.

The client is aborted when it goes away: `req.raw.on("close", () => abort.abort())` cancels the
upstream stream — the edge never blocks the event loop buffering a response (project plan §1).

### Metering

Every call records exactly once (`recordOnce`) into `gateway_calls` via
`apps/edge/src/gateway/usage.ts`: `{appId, userOid, userName, userEmail, capability: "llm", model,
inputTokens, outputTokens, outcome}` where outcome is `ok` / `error` / `quota_blocked` (the column
also admits `refusal`, reserved for content-policy stops; M4 emits the three above).

**Cut and failed streams** (a client hang-up, or an error after the upstream answered `200` with at
least one stream event) still write `outcome: error`, but freeze a best-effort charge in
`costMicroUsd` and mark the row in `errorDetail` with a trailing `;usage=measured`, `;usage=estimated`,
or `;usage=mixed`. `stopReason` is `null` on those rows — not the default `end_turn`, which would
claim a call that never finished. Per field: input is the measured count when a `usage` event (or
`done`) delivered one, else a byte estimate of the prompt; output is `max(measured, estimate)` from
relayed delta bytes. An upstream `4xx`/`5xx` before any event still records `costMicroUsd: 0` with no
marker. **Residuals:** reasoning tokens billed but never streamed are not estimated; an edge crash
mid-stream writes no row at all.

`userOid` and the two label columns are the **identity half and the display half** of the caller,
and the split is the point. `userOid` is the Entra `oid` claim since ADR-0048 (a pairwise `sub` on
rows that predate the re-base) — stable, compared, joined on, and an attribution dead end, because
the platform deliberately holds no Graph `/users` grant (ADR-0040 decision 3), so it resolves
through no directory lookup there is. `userName`/`userEmail` are the claims *captured at the moment of the
call* (`apps/edge/src/auth/identity.ts`), rendered but never compared. They are captured rather than
resolved because the only id→name map the platform has is the `sessions` row, which is swept at
expiry, while these rows are append-only — and because "who this was at the time" is the correct
audit semantic. They are null for anonymous, shared-password and dev-token callers, which have no
directory identity to capture rather than an unknown one. The single seam that produces all three
is `meterIdentity(caller)` in `apps/edge/src/auth/gate.ts`; note it must **not** be spread into
`mintInstruction` or `provider.stream`, which cross to egress carrying the opaque id alone. The portal reads this
ledger (see [registry-and-deploys.md](./registry-and-deploys.md) and `packages/shared/src/usage.ts`).

What the ledger captures is deliberately narrow — **tokens, request count, outcome, capability,
model, user, app, timestamp** — and nothing more. There is **no latency, no error-detail/message,
no session count, and no request/response size**: the row is a metering + budget primitive, not an
observability sink. Two consequences worth stating plainly:

- **Cost, as charged.** Each `gateway_calls` row carries a frozen `costMicroUsd`, computed at write
  time from a **code-resident rate table** (`packages/shared/src/pricing.ts`) — so a later rate
  change never rewrites history, and token counts are recorded alongside it (ADR-0021).
- **Append-only by grant.** `helix_edge` has `INSERT` (and `SELECT` for the budget sum) but no
  `UPDATE`/`DELETE` on `gateway_calls`, and `helix_portal` is revoked to SELECT-only as well
  (migration `20260721120000`) — no runtime role can rewrite history. There is no hash chain or
  signature: integrity rests on the DB grant set, not on cryptographic tamper-evidence, and that
  is the chosen posture rather than a committed gap (ADR-0021 — the tamper-evidence demand, from
  an unratified PM brief, was withdrawn 2026-09-17).

Calls that never reach the provider record selectively: a `quota_blocked` admission is logged (it
*was* a request the app made), but a **rejected CSRF / disallowed-model / unconfigured-capability**
call records nothing — those are policy refusals at the door, not metered usage. Anonymous calls
throttled by the per-IP limiter on public apps are also **not** metered (a ledger row per throttled
request is its own write-amplification vector under flood).

## OpenAI-compatible surface

The same runtime is exposed a second way, in the **OpenAI `chat/completions` wire format**, so an
app can use a stock OpenAI client with only a `baseURL` change (ADR-0033):

```js
const client = new OpenAI({
  baseURL: location.origin + "/_api/openai/v1",
  apiKey: "unused",              // the __Host-session cookie authenticates same-origin
  dangerouslyAllowBrowser: true, // Helix apps run in the browser
});
await client.chat.completions.create({ model: "claude-opus-4-8", messages, stream: true });
```

- **Routes:** `POST /_api/openai/v1/chat/completions` and `GET /_api/openai/v1/models` (the app's
  allowlisted models, OpenAI list shape). App hosts only; mirrored on the dev-gateway.
- **One spine, one difference.** Every policy/metering step above is identical — only the envelope
  changes. `makeLlmHandler(rt, codec)` takes an `LlmWireCodec` (`gateway/llmCodec.ts`): `nativeCodec`
  is `/_api/llm/chat` (byte-identical); `openAiCodec` (`gateway/openaiCodec.ts`) parses the OpenAI
  body into the neutral shape and frames the neutral stream back as `chat.completion.chunk` +
  `[DONE]` (or a single `chat.completion`). Errors are OpenAI-shaped (`{error:{message,type,...}}`).
- **Scope: text chat + structured output.** `tools` (a non-empty list), an affirmative `tool_choice`,
  `role:"tool"`, multimodal (array) content, and the behaviour-changing sampling params
  (`seed`, `n`, `logit_bias`, `presence_penalty`, `frequency_penalty`, `logprobs`,
  `top_logprobs`) are rejected with a clear `400` (naming the field in `error.param`) — never silently
  dropped. Opting *out* of tools (`tool_choice:"none"`, empty `tools:[]`) is served. `system`/
  `developer` messages are hoisted into the neutral top-level `system`; `temperature`, `top_p`, and
  `stop` are forwarded to the vendor. `response_format` **is** served — see
  [Structured output](#structured-output) below.
- **`max_tokens` follows OpenAI convention.** Omit it and the model's own maximum applies (not a
  forced default) — `max_tokens`/`max_completion_tokens` → the neutral optional `maxTokens`, and the
  OpenAI body builder omits the upstream cap when it's unset. o-series reasoning models instead take
  `max_completion_tokens`, **floored** (catalog `minCompletionTokens`, ~25k) so reasoning tokens can't
  starve visible output and leave a billed-empty answer.

### Structured output

Constrain a completion to a JSON schema, on **both** surfaces (ADR-0034). This is the one
"behaviour-changing output param" the gateway serves, and the reason it can is that both vendors
return schema-constrained JSON as **ordinary text** — Anthropic in `text_delta` blocks, OpenAI in
`delta.content`. So it rides the existing delta path: no new `LlmStreamEvent` variant, no codec
framing change, no change to `mapAnthropicStream`/`mapOpenAiStream`. (Tool calling is a non-text
content block, which is exactly why it is still deferred.)

The neutral field is `responseFormat` on `LlmChatRequestSchema`, and each side translates:

| | Shape |
| --- | --- |
| Neutral (`/_api/llm/chat`) | `responseFormat: {type:"json_schema", name?, schema}` |
| OpenAI surface | `response_format: {type:"json_schema", json_schema:{name, schema}}` |
| → Anthropic upstream | `output_config: {format:{type:"json_schema", schema}}` (`name` is not forwarded) |
| → OpenAI upstream | `response_format` as above; `name` defaults to `"response"` (OpenAI requires one) |

**Enforcement is unconditional — there is no `strict` knob.** Anthropic's
`output_config.format` has no best-effort mode, so honouring a `strict:false` would mean the
same request yields schema-violating JSON on `gpt-*` and conforming JSON on `claude-*` — the
provider leak this seam exists to prevent. The OpenAI upstream is always sent `strict: true`,
and an incoming `json_schema.strict` on the OpenAI surface is **accepted and ignored** rather
than rejected (stock clients routinely omit it, and OpenAI's own default is `false`, so
refusing would break them — while enforcing is strictly stronger than what a `false` asks for).

The response envelope is unchanged: the JSON arrives as `content` (native) or
`choices[].message.content` (OpenAI), and the caller `JSON.parse`s it.

Four refusals, all `400` and all before any upstream call:

- **`json_schema` only.** OpenAI's looser `{type:"json_object"}` has no Anthropic equivalent, so
  serving it would make behaviour depend on which vendor backs the model — rejected, naming
  `response_format.type`. `{type:"text"}` is OpenAI's explicit default and is served as a no-op
  (same principle as `tool_choice:"none"`), as is `response_format: null` — clients that
  serialize every field send null to mean "no structured output".
- **`json_schema.description` is rejected**, not silently dropped. It is honorable on the OpenAI
  path but has no Anthropic equivalent, so forwarding it would leak the backing vendor the same
  way `json_object` would.
- **Per-model.** Support is not uniform within either vendor's line-up, so it's a catalog bit
   (`ModelPrice.structuredOutputs`, alongside `reasoning`). Today: `claude-fable-5-1`,
   `claude-fable-5`, `claude-opus-5`, `claude-opus-4-8`, `claude-sonnet-5`, `claude-haiku-4-5` and
   every `gpt-*` can; `claude-opus-4-7`, `claude-opus-4-6`, `claude-sonnet-4-6` cannot. Those
   three stay fully usable for text chat.
- **Schema budget.** The schema is app-supplied input on the trusted path, walked before the quota
  check, so it must have an object root and stay within ≤ 32,768 characters serialized and ≤ 12
  levels deep. Beyond those guards it is forwarded as-is and the **vendor** validates its own JSON
  Schema subset — the same division of labour as `temperature`. Practically that means writing to
  the stricter of the two subsets (`additionalProperties: false`, every key in `required`, no
  recursion, no `minLength`/`minimum`-style constraints).

**A vendor-rejected schema is the app's fault, and says so.** A schema that passes the boundary
guards but falls outside the vendor's strict subset draws a `400` from the vendor. That used to
flatten to `502 internal` — telling the app to retry something that could never succeed, and
attributing an app bug to the platform. `describeError` now branches on the `upstreamStatus` that
`LlmProviderError` already carried: an upstream `400` becomes `400 validation_failed`, naming
`responseFormat` when a schema was in play, and an upstream `429` becomes `429 rate_limited` with
the vendor's `retry-after` (egress already forwards the header; the edge coerces it to integer
delay-seconds or falls back to 5). The vendor's own message is **never echoed** (it can
quote request content, and on an auth failure the key); it goes to the ledger's internal
`errorDetail` instead, which walks the `cause` chain so the wire-level code survives.

**Truncation.** A schema-constrained reply that hits `maxTokens` comes back as unparseable JSON —
prose degrades gracefully, JSON does not. Check `stopReason !== "max_tokens"` before parsing, and
note that omitting `maxTokens` on a `claude-*` model means `1024`.

**Streaming error framing.** `startStream` is lazy, so a failure *before the first delta* has
written nothing and answers with a real HTTP status — the same as every other pre-stream refusal
on this route. Only once the head is out does a failure travel in-band as an `error` frame. This
applies to all provider failures, not just structured output.

**No manifest grant.** Structured output adds no egress path, no secret, and no new cost class —
spend is already bounded by `dollarsPerDay` — so any app holding an `llm` grant can use it.

### Multiple upstreams (Anthropic + OpenAI)

Models route to a vendor by the catalog's `provider` field (`packages/shared/src/pricing.ts`) —
`providerForModel` — so pricing and routing share one source of truth (no id-space overlap between
`claude-*` and `gpt-*`/`o*`). `RoutingLlmProvider` holds one `EgressLlmProvider` per vendor; a curated
model whose upstream isn't wired on this edge 503s before a stream opens.

The OpenAI upstream is an **OpenAI-compatible base URL** — `api.openai.com` today, a Warden URL later
(same code path). It is wired **symmetrically with Anthropic**: the connection name defaults to
`openai` (`EDGE_LLM_OPENAI_CONNECTION`, like Anthropic's default `anthropic`) and the endpoint to
`https://api.openai.com` (`EDGE_LLM_OPENAI_ENDPOINT`). So **enabling OpenAI is just seeding its key** —
no dedicated toggle:

- Create a `platform`-scoped secret named `openai` with the OpenAI key via `POST /api/v1/secrets`
  (`scope:"platform"`); the default `header-bearer` injection makes egress send
  `Authorization: Bearer <key>`. The edge never holds the key (ADR-0008). Override the name/host only
  to point at a non-default upstream (e.g. Warden).

A deployment that doesn't want OpenAI simply doesn't seed that secret and doesn't allowlist `gpt-*`
models; an app that allowlists one without the secret present gets a `502` at call time — exactly as
an unseeded Anthropic key would. Seeded OpenAI models: `gpt-6-astra`, `gpt-5.6-{sol,terra,luna}`,
`gpt-5.1`, `gpt-5-{mini,nano}`, plus the retained previous generations `gpt-4o` and
`gpt-4.1{,-mini,-nano}`. (`gpt-4o-mini`, `o3` and `o4-mini` were cut from the catalog on 2026-09-16 —
Azure AI Foundry refuses models whose default version is `Deprecating`, and the current generation
covers their price points.)

**`reasoning` is set on everything from GPT-5 on, not just the o-series.** The flag decides whether
the edge sends `max_completion_tokens` or the deprecated `max_tokens`; OpenAI's reasoning models
reject the latter outright, so a current-generation model added without the flag 400s on every call.
`pricing.test.ts` pins the split, and pins that no `claude-*` model ever carries it.

**Rates last verified 2026-09-14** against both vendors' pricing pages; they drive the cost gate, so
re-verify rather than trusting that date. Two things moved at that check: Claude Sonnet 5's
introductory `$2/$10` became its standard price (the scheduled rise to `$3/$15` was cancelled), and
Claude Fable 5.1 arrived billing **cache reads at 0.025x** base input instead of the universal 0.1x —
which is why the read multiplier is now per-model (`ModelPrice.cacheReadMultiplier`, defaulting to
`CACHE_READ_MULTIPLIER`) rather than one platform-wide constant. Note OpenAI's cached-input discount
is not a flat 0.1x either (`gpt-4o` 0.5x, `gpt-4.1` 0.25x, current generation 0.1x), so if
`mapOpenAiStream` ever maps OpenAI's `cached_tokens`, those need per-model rates too.

### Azure AI Foundry upstreams (ADR-0046)

A customer-cloud install can point **both families at one Azure AI Foundry account** instead of the
first-party vendors — inference then bills to and stays inside the customer's subscription. Foundry
serves the two wire protocols we already speak from one origin: the Messages API at
`<origin>/anthropic/v1/messages` and the versionless v1 OpenAI API at
`<origin>/openai/v1/chat/completions`. The edge config is exactly that split:

- `EDGE_LLM_ENDPOINT` / `EDGE_LLM_OPENAI_ENDPOINT` = the account origin (`https://<account>.services.ai.azure.com`)
- `EDGE_LLM_ANTHROPIC_PATH` / `EDGE_LLM_OPENAI_PATH` = the prefixed paths above (endpoints are
  origin-only, so the prefix lives here — the defaults remain the first-party shapes)
- `EDGE_LLM_ANTHROPIC_CONNECTION` / `EDGE_LLM_OPENAI_CONNECTION` = the credential names (below)

Routing, allowlists, pricing and metering are untouched: models still route by the catalog's
`provider` field, and the Foundry **deployment name equals the catalog model id** (the edge forwards
the app-requested model verbatim and Foundry routes on deployment name), so no mapping layer exists.
Azure's RAI `content_filter` finish reason maps to `refusal` already.

The credential has two modes (ADR-0046 has the decision):

- **Keyless (the deployed default).** No secret exists anywhere: the egress managed identity holds
  `Cognitive Services User` + `Cognitive Services OpenAI User` on the account, and egress mints an
  Entra token (scope `https://ai.azure.com/.default`) per call, injecting `Authorization: Bearer`.
  Engaged only for connection names allowlisted in `EGRESS_MANAGED_IDENTITY_CONNECTIONS`
  (`foundry=<account-host>,foundry-openai=<account-host>`), only on the `llm` capability, and only
  onto the pinned host — a forged instruction naming the connection but a foreign origin gets
  nothing. When `infra/azure` creates the account (`deployFoundry`), all of this is wired by the
  template; the account is deployed `disableLocalAuth` (no usable keys exist).
- **Seeded key (local dev / BYO-with-key).** A stored `platform` row always wins over the mint, so
  dev — which has no managed identity — seeds the Foundry account key under the same connection
  names and runs the identical code path:
  `seed:llm -- <key> --name foundry` (x-api-key) and `--name foundry-openai --recipe api-key`.

`infra/azure/README.md` ("Azure AI Foundry") covers the operator side: the `deployFoundry` flag,
model/quota/region caveats, and the BYO recipe.

## Try it

`examples/chatbot` streams Claude through this gateway — the app ships only a frontend and never
holds an API key. See [examples.md](./examples.md).

## Planned / not yet built

- **Tool calling** on both surfaces — `tools`/`tool_calls` translation needs the neutral-seam
  changes structured output did *not* (a tool call is a non-text content block, so it needs new
  `LlmStreamEvent` variants and new codec framing); deferred (ADR-0033/0034). Other modalities
  (`/v1/embeddings`, audio) are likewise additive behind the same seams.
- **`response_format: {type:"json_object"}`** — the loose JSON mode is refused rather than
  emulated, since Anthropic has no equivalent (ADR-0034). Revisit only if a permissive
  open-object schema turns out to be a faithful translation rather than a fake.
- **OpenAI `refusal` passthrough** — a model declining under a schema is already mapped to the
  neutral `refusal` stop reason and metered as `outcome:"refusal"`, but the refusal *string* isn't
  surfaced on the response envelope; doing so needs the seam widening ADR-0034 avoids.
- **Cost display / pricing source** — each call already records a frozen `costMicroUsd` from a
  code-resident rate table (ADR-0021); surfacing spend in the dashboards and maintaining the rate
  table are the remaining work (`packages/shared/src/{usage,pricing}.ts`).
- **MCP-as-REST** — `capabilities.mcp` exists in the manifest but has no gateway transport yet
  (see [capabilities-and-manifests.md](./capabilities-and-manifests.md) and
  `docs/design/custom-backends.md`).
