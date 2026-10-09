import { z } from "zod";
import { ProviderRefSchema } from "./providers.js";
import { VisibilitySchema } from "./visibility.js";

/**
 * The per-app manifest (architecture §6.3) — editable in the portal, versioned.
 * It declares the capabilities the gateway will enforce. Grants above a baseline
 * (arbitrary MCP servers / external origins, high LLM budgets) require admin
 * approval; that policy lives in the control plane, not in this shape.
 *
 * Mirrors the YAML in §6.3:
 *
 *   app: cost-explorer
 *   visibility: internal
 *   capabilities:
 *     llm: { models: [claude-haiku-4-5, claude-fable-5], dollars_per_day: 5.00 }
 *     data: { user: true, collections: [contacts] }
 *     mcp: [azure-billing]
 *     external_origins: []
 */
export const LlmCapabilitySchema = z.object({
  models: z.array(z.string()).default([]),
  /**
   * Per-app daily LLM spend cap in USD; unset ⇒ the install default (the approval
   * baseline unless the operator changed it). Denominated in
   * dollars (not tokens) so the cap means the same thing across models — the
   * edge prices each call via `@azx-pbc/shared` pricing and enforces a daily +
   * rolling-hour burst window off the frozen `costMicroUsd` ledger column.
   */
  dollarsPerDay: z.number().positive().optional(),
});
export type LlmCapability = z.infer<typeof LlmCapabilitySchema>;

/**
 * App-data grants (app-data design §3/§4). The three scopes are named access
 * patterns, not a symmetric KV — the writer and reader can be different
 * principals, so read and write are independent grants:
 *  - `user`: per-user private store, auto-partitioned by the session user (§3.1).
 *  - `collections`: append-only from the app; the owner drains them via the
 *    portal. There is deliberately NO app-facing read (§3.2) — the absence is
 *    the security property.
 *  - `sharedRead` / `sharedWrite`: app-scoped, world-readable keys (§3.3). Rare,
 *    explicit, and dangerous; a write grant never implies a read grant.
 *  - `sharedReadPrefixes` / `sharedWritePrefixes` (ADR-0042): the same grants as
 *    *prefixes* — a key is authorized if it matches a literal grant OR starts
 *    with a granted prefix. What this buys is runtime-invented keys: a literal
 *    array is fixed at deploy time, so creating a record meant editing the
 *    manifest and redeploying. Prefix-only (`startsWith`, no pattern language);
 *    elevated at approval time because one element covers unboundedly many keys.
 *
 * Every grant string in this block — collection names, literal keys, prefixes —
 * is a printable-ASCII identifier (ADR-0043, `isValidDataKey`); the VALUES an
 * app stores remain arbitrary Unicode JSON.
 * `writesPerDay` / `bytesPerDay` bound abuse on the open append surface (§7).
 */

/** Key length cap. With the printable-ASCII rule below, chars ARE bytes. */
const KEY_MAX_CHARS = 256;

/**
 * Printable ASCII, the whole of it — `0x20` (space) through `0x7E` (`~`).
 * A positive allowlist, not a blocklist: a blocklist has to anticipate the
 * whole of Unicode's esoterica, and it already missed the Cf format
 * characters (bidi controls, zero-width joiners) that this rule exists to
 * keep out of grant strings.
 */
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/**
 * Is this a legal app-data key, prefix, or collection name? (ADR-0043.)
 *
 * **Printable ASCII, 1–256 characters, no leading/trailing space.** Keys are
 * *identifiers* — `record:<id>`, `stock`, `prefs` — and identifiers don't need
 * the rest of Unicode; VALUES are where human language lives, and they stay
 * arbitrary JSON. Four things make the character set a security decision
 * rather than a style one:
 *
 *  - a key is used in four trusted places — URL path segment, authorization
 *    grant, approval-delta path, admin-facing diff — and the old "no control
 *    characters" blocklist passed Cf *format* characters: a bidi control
 *    (U+202E) in a `sharedReadPrefixes` grant can visually reorder the diff an
 *    admin reads, and a zero-width space hides entirely. Same reasoning as
 *    `isValidServiceWorkerScope`'s allowlist, which the edge adopted for
 *    exactly this class of value;
 *  - homoglyph grants (a Cyrillic `а` in `record:`) are invisible to a human
 *    reviewer and authorize different bytes than they appear to;
 *  - un-normalized Unicode encodes one visual key several ways (precomposed
 *    `é` vs `e`+combining accent) — distinct keys, identical to every reader;
 *  - every string ordering (JS code-unit, UTF-8 bytewise, any collation)
 *    coincides on ASCII, which removes the astral-plane keyset divergence
 *    class at the root instead of compensating for it.
 *
 * The no-edge-space rule also refuses the all-space and padded grants that
 * are invisible in a diff.
 */
export function isValidDataKey(key: string): boolean {
  return (
    key.length > 0 &&
    key.length <= KEY_MAX_CHARS &&
    PRINTABLE_ASCII.test(key) &&
    // After the ASCII test this can only be a leading/trailing 0x20 — but it
    // is the one character in the allowlist that is invisible at a grant's
    // edges, so it gets its own rule.
    key === key.trim()
  );
}

const DATA_KEY_RULE =
  "must be 1–256 printable ASCII characters (0x20–0x7E) with no leading or trailing space";

/** The zod form of {@link isValidDataKey} — every grant string in the data block. */
const DataKeySchema = z.string().refine(isValidDataKey, { message: DATA_KEY_RULE });

export const DataCapabilitySchema = z
  .object({
    user: z.boolean().default(false),
    collections: z.array(DataKeySchema).default([]),
    sharedRead: z.array(DataKeySchema).default([]),
    sharedWrite: z.array(DataKeySchema).default([]),
    /** ADR-0042: authorize every key starting with one of these prefixes (read). */
    sharedReadPrefixes: z.array(DataKeySchema).default([]),
    /** ADR-0042: authorize every key starting with one of these prefixes (write). */
    sharedWritePrefixes: z.array(DataKeySchema).default([]),
    writesPerDay: z.int().positive().optional(),
    bytesPerDay: z.int().positive().optional(),
  })
  /**
   * A write-prefix grant REQUIRES a writesPerDay budget (ADR-0042 review
   * finding 3). Before prefixes, the literal `sharedWrite` array bounded the
   * rows an app could ever hold — a flood could overwrite N keys, never create
   * new ones. With `sharedWritePrefixes`, every `If-None-Match: *` PUT mints a
   * NEW row, there is no shared DELETE to reclaim any of it (TODO.md), and an
   * unset budget is unlimited (`admitWrite`). Read prefixes are exempt: they
   * cannot create rows, and listing is already bounded by the page cap —
   * forcing a budget there would tax a capability the app cannot abuse this
   * way. The parse-level coupling is what makes the grant and its bound one
   * approval decision: the portal cannot store the one without the other.
   */
  .superRefine((d, ctx) => {
    if (d.sharedWritePrefixes.length > 0 && d.writesPerDay === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["writesPerDay"],
        message:
          "a writesPerDay budget is required alongside sharedWritePrefixes — a prefix grant allows runtime row creation, so the grant and its bound are approved together (ADR-0042)",
      });
    }
  });
export type DataCapability = z.infer<typeof DataCapabilitySchema>;

/**
 * A proxied outbound origin (fetch-proxy design §4/§5). An origin listed here is
 * reached **through `/_api/fetch`** (the `helix-egress` mechanism plane) — audited,
 * metered, SSRF-controlled — as opposed to a `direct` browser call widened into
 * CSP via `externalOrigins`. The credential select is 3-way and mutually
 * exclusive (one origin expresses at most one credential
 * source, enforced below):
 *  - neither `connection` nor `provider` ⇒ a keyless proxied call;
 *  - `connection` names a stored secret (`docs/design/secrets-and-connections.md`)
 *    injected server-side;
 *  - `provider` names an OAuth provider whose user
 *    connection egress injects; `required` is the app's dependency hint for
 *    that binding and nothing more — it never blocks app loading or triggers
 *    anything platform-side.
 *
 * **Strict**: unknown keys are rejected, not stripped. This schema
 * is re-parsed by every plane that reads a manifest; a future field an older
 * plane does not know must fail that parse closed rather than silently
 * disappear — the silent-strip version skew is the hazard the strict parse
 * exists to close.
 */
export const FetchConnectionSchema = z
  .strictObject({
    origin: z.url(),
    connection: z.string().min(1).optional(),
    provider: ProviderRefSchema.optional(),
    required: z.boolean().optional(),
  })
  .superRefine((c, ctx) => {
    if (c.connection !== undefined && c.provider !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["provider"],
        message:
          "an origin binds at most one credential source — declare a stored secret (connection) or an OAuth provider (provider), not both",
      });
    }
  });
export type FetchConnection = z.infer<typeof FetchConnectionSchema>;

/** The fetch-proxy capability: proxied origins + ergonomics + abuse budget. */
export const FetchCapabilitySchema = z.object({
  /**
   * Legacy view of the fetch-shim grant. The grant is declared first-class as
   * {@link ShimCapabilitySchema} (`capabilities.shim.fetch`); this boolean is
   * the pre-`capabilities.shim` spelling, still accepted on input and kept synchronized
   * with the canonical block on every parse (see {@link CapabilitiesSchema}) —
   * new manifests should declare `capabilities.shim`, not this field.
   */
  shim: z.boolean().default(false),
  /** Origins reached through the proxy (mode `proxy`); direct stays in `externalOrigins`. */
  origins: z.array(FetchConnectionSchema).default([]),
  /** Per-app daily proxied-request budget; unset ⇒ unbounded (fetch-proxy §7). */
  requestsPerDay: z.int().positive().optional(),
});
export type FetchCapability = z.infer<typeof FetchCapabilitySchema>;

/**
 * The injected platform helpers an app opts into (the
 * platform does not inject JavaScript into app documents unbidden). Both
 * sub-options are serve-time ergonomics, never a privilege grant: they stay at
 * the fetch-shim block's low-risk baseline classification in the approval
 * classifier (`packages/shared/src/approval.ts`).
 *
 *  - `fetch`: the transparent `fetch`/XHR rewrite to the proxy (fetch-proxy §3.2).
 *  - `connect`: the `window.helix.connect()` consent-popup helper —
 *    the raw platform entry stays available without it.
 */
export const ShimCapabilitySchema = z.object({
  fetch: z.boolean().default(false),
  connect: z.boolean().default(false),
});
export type ShimCapability = z.infer<typeof ShimCapabilitySchema>;

/**
 * Is `scope` a legal service-worker scope prefix (ADR-0035 §3)? Exported so the
 * edge can re-run the identical rule when it re-parses the grant fail-closed.
 *
 * Deny-by-default: each segment must be **unreserved URL characters only**
 * (RFC 3986 `A-Za-z0-9-._~`). A positive allowlist rather than a blocklist
 * because this value is used twice in the trusted path — as a path prefix
 * matched against request URLs, and as the `Service-Worker-Allowed` *response
 * header value*, where a stray CR/LF would be header injection. Percent-escapes
 * are refused outright, mirroring `normalizeRequestPath`'s posture: a scope that
 * needs encoding could never match a servable path anyway.
 *
 * Two rules carry the security weight:
 *  - **Root is refused.** A root-scoped worker would see the handoff token on
 *    `/_auth/complete`, which is why service workers were banned at all
 *    (architecture Appendix A.3).
 *  - **Any `_`-leading first segment is refused** — a rule, not an enumeration
 *    of `_auth`/`_api`/`_helix`/`_csp-report`, so it stays correct when a
 *    platform namespace is added.
 */
const SCOPE_SEGMENT = /^[A-Za-z0-9\-._~]+$/;

export function isValidServiceWorkerScope(scope: string): boolean {
  if (!scope.startsWith("/") || !scope.endsWith("/")) return false;
  // Split the interior, WITHOUT filtering empties: an empty segment means a
  // doubled slash, and `/app//` must be refused here rather than silently
  // accepted. The edge rejects it anyway (`normalizeRequestPath` collapses the
  // double slash, so the round-trip comparison in `parseOfflineGrant` fails),
  // and two validators disagreeing on the accepted set is exactly the drift the
  // double validation exists to avoid: the owner would get an approved,
  // elevated grant that projects to nothing, with no diagnostic anywhere.
  // `"/".slice(1, -1)` is `""` → one empty segment → root stays refused.
  const segments = scope.slice(1, -1).split("/");
  const first = segments[0];
  if (first === undefined) return false;
  if (segments.some((s) => s === "" || s === "." || s === ".." || !SCOPE_SEGMENT.test(s))) {
    return false;
  }
  return !first.startsWith("_");
}

/**
 * The offline capability (ADR-0035): the app opts into a **platform-authored**
 * service worker, confined to `scope`. The app ships no worker code — the edge
 * serves the worker and injects its registration — so this grant is a scope
 * declaration, not a pointer at app-supplied bytes.
 *
 * It buys **cold boot** (the document and its static assets answer with no
 * network) and nothing else: durable state, large-asset caching and queued-work
 * drain are ordinary page JS that every app already has without a grant.
 */
export const OfflineCapabilitySchema = z.object({
  /**
   * URL path prefix the worker controls, e.g. `/app/`. Leading and trailing
   * slash required; never root, never a `_`-prefixed platform namespace.
   */
  scope: z.string().refine(isValidServiceWorkerScope, {
    message:
      "scope must be a non-root path prefix with a leading and trailing slash, and must not start with a reserved `_` segment (e.g. `/app/`)",
  }),
});
export type OfflineCapability = z.infer<typeof OfflineCapabilitySchema>;

/**
 * The parsed capabilities shape — the transform below normalizes the legacy
 * shim alias, so this is declared by hand rather than inferred: inferring the
 * transform's object-literal return marks every optional key
 * required-with-`undefined`, which would break every partial `Capabilities`
 * literal consumers build. A type alias (not an interface) so the shape keeps
 * its implicit index signature — the portal stores parsed capabilities
 * straight into a Prisma `InputJsonValue` column. Kept adjacent to the schema
 * so the two cannot drift.
 */
export type Capabilities = {
  llm?: LlmCapability;
  data?: DataCapability;
  mcp: string[];
  externalOrigins: string[];
  fetch?: FetchCapability;
  offline?: OfflineCapability;
  shim?: ShimCapability;
};

export const CapabilitiesSchema = z
  .object({
    llm: LlmCapabilitySchema.optional(),
    data: DataCapabilitySchema.optional(),
    /** Platform-registered MCP servers this app may reach (§6.1, exposed as REST). */
    mcp: z.array(z.string()).default([]),
    /** Extra CSP `connect-src` origins for **direct** browser calls (§4.4). */
    externalOrigins: z.array(z.url()).default([]),
    /** Governed outbound HTTP via the fetch-proxy / egress plane (in build, M4.5). */
    fetch: FetchCapabilitySchema.optional(),
    /** Platform-owned, scope-confined service worker for offline cold boot (ADR-0035). */
    offline: OfflineCapabilitySchema.optional(),
    /** Injected platform helpers — the first-class shim grant. */
    shim: ShimCapabilitySchema.optional(),
  })
  /**
   * Legacy shim-alias normalization: `capabilities.fetch.shim`
   * predates the first-class block, and both spellings must stay behaviorally
   * indistinguishable after parse — existing boolean-shim apps keep their grant,
   * and the edge's per-block fetch parse keeps reading the synchronized boolean
   * until the projection migrates to the canonical form. On every parse the two
   * views are OR-merged and written back to BOTH positions, so `parse(oldForm)`
   * and `parse(newForm)` produce the same capability set and the merge is
   * idempotent. The one way to lose a grant would be a parse that dropped the
   * alias's `true` because a stale canonical block said `false` (or vice versa),
   * so a conflict merges ON — the same direction every default here reads.
   * Consumers that APPLY a shim change must write both views (the classifier's
   * `applyScalar` does); a parse alone can never desynchronize them.
   */
  .transform((caps): Capabilities => {
    const legacyShim = caps.fetch?.shim ?? false;
    const fetchOn = legacyShim || (caps.shim?.fetch ?? false);
    const connectOn = caps.shim?.connect ?? false;
    // `shim.fetch: true` without a fetch block is the new spelling of today's
    // `{fetch: {shim: true}}` — materialize the block so the parsed shapes of
    // the old and new forms are identical, not merely equivalent.
    const fetch = caps.fetch ?? (fetchOn ? { shim: fetchOn, origins: [] } : undefined);
    return {
      ...caps,
      fetch: fetch === undefined ? undefined : { ...fetch, shim: fetchOn },
      ...(fetchOn || connectOn ? { shim: { fetch: fetchOn, connect: connectOn } } : {}),
    };
  });

/**
 * Per-binding effectiveness for one provider-bound origin, computed by the
 * portal when it serves a manifest read. The SPA renders the
 * Reapproval-needed badge from this alone — no second request — and the owner
 * resubmits by saving the manifest again.
 */
export const ProviderBindingStatusSchema = z.strictObject({
  /** The manifest origin as declared (matches `FetchConnection.origin`). */
  origin: z.string(),
  /** The bound provider reference. */
  ref: ProviderRefSchema,
  /**
   * Whether an approval that granted this binding still matches the provider
   * row's current identity — the {@link isProviderBindingEffective} rule
   * (the one definition; the portal never re-derives the comparison). `false`
   * means the provider was deleted or a sensitive edit stale-dated the stamp.
   */
  effective: z.boolean(),
});
export type ProviderBindingStatus = z.infer<typeof ProviderBindingStatusSchema>;

export const AppManifestSchema = z.object({
  /** App slug; matches `App.slug`. */
  app: z.string().min(1),
  visibility: VisibilitySchema,
  capabilities: CapabilitiesSchema.default({ mcp: [], externalOrigins: [] }),
  /**
   * Effectiveness of every provider-bound origin in `capabilities`, computed
   * server-side on the read (never stored). Absent when the manifest declares
   * no provider binding — every payload without one keeps its exact shape.
   */
  providerBindings: z.array(ProviderBindingStatusSchema).optional(),
});
export type AppManifest = z.infer<typeof AppManifestSchema>;
