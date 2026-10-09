import { z } from "zod";
import { AppSchema } from "./app.js";
import { EnvSchema } from "./env.js";
import { CapabilitiesSchema, type Capabilities, type FetchConnection } from "./manifest.js";
import { AppManifestSchema } from "./manifest.js";
import { MODEL_PRICING } from "./pricing.js";
import { ProviderRefSchema } from "./providers.js";
import { type VisibilityMode } from "./visibility.js";

/**
 * Approvals (design doc `docs/design/approvals.md`). The control-plane gate on
 * *writes* to the effective policy the edge already reads. The `apps` row holds
 * only effective state; "requested state" is the set of open ApprovalRequest
 * rows. This module is the policy spine, kept here in `@azx-pbc/shared` so the
 * portal (gating) and the SPA (pre-submit "this will need approval" warning)
 * read the identical thresholds and run the identical classifier (§3).
 */

/** Queue sort + per-delta severity. Ordered low < med < high. */
export const RISK_LEVELS = ["low", "med", "high"] as const;
export const RiskSchema = z.enum(RISK_LEVELS);
export type Risk = z.infer<typeof RiskSchema>;

const RISK_ORDER: Record<Risk, number> = { low: 0, med: 1, high: 2 };
export function maxRisk(risks: Risk[]): Risk {
  return risks.reduce<Risk>((acc, r) => (RISK_ORDER[r] > RISK_ORDER[acc] ? r : acc), "low");
}

export const APPROVAL_STATUSES = [
  "pending",
  "approved",
  "denied",
  "withdrawn",
  "needs_changes",
] as const;
export const ApprovalStatusSchema = z.enum(APPROVAL_STATUSES);
export type ApprovalStatus = z.infer<typeof ApprovalStatusSchema>;

/**
 * One env-partitioned provider row's identity, as it read when an approval
 * request was filed. The unit of {@link Delta.providerStamps}.
 */
export const ProviderStampSchema = z.strictObject({
  /** The env-unique reference the manifest binds (the catalogue/manifest key). */
  ref: ProviderRefSchema,
  /** Which partition the stamped row lives in — a ref may exist in both. */
  env: EnvSchema,
  /** The surrogate row id — delete+recreate mints a new one, dangling old stamps. */
  providerId: z.uuid(),
  /** The row's revision at filing; a sensitive edit advances it. */
  revision: z.int().positive(),
});
export type ProviderStamp = z.infer<typeof ProviderStampSchema>;

/**
 * A typed, path-keyed change. `path` is the human-facing key (rendered in the
 * diff and the audit trail); for array membership it carries the affected item
 * (`mcp[+pagerduty]`, `externalOrigins[-https://api.foo.com]`). `from`/`to` hold
 * the scalar values for conflict detection and diff render.
 */
export const DeltaSchema = z.object({
  path: z.string(),
  from: z.union([z.string(), z.number(), z.boolean()]).optional(),
  to: z.union([z.string(), z.number(), z.boolean()]).optional(),
  /**
   * The provider stamps recorded **at filing** for a provider-bound origin
   * delta — one per env-partitioned `connection_providers` row that
   * existed under the bound ref when the request was filed (an
   * approval records the provider's `ref` + `providerId` + `revision`, and
   * env partitioning makes a ref's full identity the set of its rows).
   *
   * This is the payload half of the apply-time conflict: approving a request
   * whose stamps no longer match the provider's current identity/revision
   * approves nothing — an old pending approval cannot approve access to a
   * newer configuration. Consumers read the rule itself from
   * {@link isProviderBindingEffective}; none re-derives the comparison.
   */
  providerStamps: z.array(ProviderStampSchema).optional(),
  /**
   * The requesting app's visibility **at filing**: `true` when the app was
   * `public`, `false` (stamped as not-public) otherwise. The
   * warning — a public app's anonymous visitors can never connect a vendor
   * account — is data on the request, so the queue card needs no extra fetch.
   * The flag never auto-rejects.
   */
  publicApp: z.boolean().optional(),
  /**
   * This delta's own severity as classified at filing — what the request-level
   * `risk` is the max of. Absent on requests filed before the field existed
   * (deltas are stored as JSON, so nothing backfills them); renderers fall
   * back to the aggregate rather than guessing.
   */
  risk: RiskSchema.optional(),
});
export type Delta = z.infer<typeof DeltaSchema>;

/**
 * The binding-effectiveness rule (the ONE definition): an app's provider
 * binding is effective
 * exactly when the approval that granted it filed a stamp matching the
 * provider row's **current** identity — same surrogate `id` (delete+recreate
 * under the same ref mints a new one), same `ref`, same `revision` (every
 * sensitive edit advances it). A `null`/`undefined` current row — the provider
 * was deleted, or never existed — is never effective.
 *
 * Consumers pass the filed stamp and the row they loaded; none re-derives the
 * comparison:
 *  - the portal's approve route (the apply-time conflict — a stale stamp is a
 *    409 that approves nothing),
 *  - the manifest read (per-binding effectiveness → the SPA's Reapproval-needed
 *    badge),
 *  - the consent consult (`not_available` for an ineffective binding),
 *  - the invalidation transaction, whose revision bump is what makes
 *    previously-stamped bindings ineffective.
 */
export function isProviderBindingEffective(
  stamp: ProviderStamp,
  current: { id: string; ref: string; revision: number } | null | undefined,
): boolean {
  return (
    current !== null &&
    current !== undefined &&
    current.id === stamp.providerId &&
    current.ref === stamp.ref &&
    current.revision === stamp.revision
  );
}

/**
 * Prior-decision context for a *pending* request, joined into the global admin
 * queue so a reviewer sees at a glance that the same (or a related) grant was
 * already refused (issue #26). A refile is byte-for-byte identical to a
 * first-time request otherwise. Read-side only — computed from sibling rows,
 * never stored. Scoped to the same app; `denied` is the signal that raises the
 * flag, other decided states are context. Present only when the app has prior
 * decided requests (omitted ⇒ a first-time request, unchanged wire shape).
 */
export const PriorDecisionsSchema = z.object({
  /** Prior *decided* (non-pending) requests on this app — the history count. */
  total: z.number().int().nonnegative(),
  /** Prior denied requests touching an overlapping policy area (quiet signal). */
  deniedSameArea: z.number().int().nonnegative(),
  /** Prior denied requests sharing an exact delta path (loud signal; ⊆ area). */
  deniedSameGrant: z.number().int().nonnegative(),
  /** The most recent decided request (any status), for the "last decision" line. */
  last: z
    .object({
      status: ApprovalStatusSchema,
      note: z.string().nullable(),
      decidedBy: z.string().nullable(),
      decidedAt: z.string(),
    })
    .optional(),
});
export type PriorDecisions = z.infer<typeof PriorDecisionsSchema>;

/** The stored/served approval request — mirrors the Prisma model (§2). */
export const ApprovalRequestSchema = z.object({
  id: z.string(),
  appId: z.string(),
  /** Joined for the admin queue / banner; not a column. */
  appSlug: z.string().optional(),
  appDisplayName: z.string().optional(),
  status: ApprovalStatusSchema,
  risk: RiskSchema,
  deltas: z.array(DeltaSchema),
  baseSnapshot: z.unknown(),
  requestedBy: z.string(),
  reason: z.string().nullable().optional(),
  decidedBy: z.string().nullable().optional(),
  decisionNote: z.string().nullable().optional(),
  createdAt: z.string(),
  decidedAt: z.string().nullable().optional(),
  /** Sibling-decision context for the admin queue (issue #26); read-side only. */
  priorDecisions: PriorDecisionsSchema.optional(),
});
export type ApprovalRequest = z.infer<typeof ApprovalRequestSchema>;

/** Response of `PUT /api/v1/apps/:slug/manifest` under the write-gate (§3). */
export const ManifestUpdateResultSchema = z.object({
  manifest: AppManifestSchema,
  applied: z.array(DeltaSchema),
  pending: z.string().nullable(),
});
export type ManifestUpdateResult = z.infer<typeof ManifestUpdateResultSchema>;

/** Response of `POST /api/v1/apps/:slug/visibility` under the write-gate (§3). */
export const VisibilityUpdateResultSchema = z.object({
  app: AppSchema,
  applied: z.array(DeltaSchema),
  pending: z.string().nullable(),
});
export type VisibilityUpdateResult = z.infer<typeof VisibilityUpdateResultSchema>;

/** Body for a reviewer decision (`deny` / `needs_changes` require a note). */
export const ApprovalDecisionRequestSchema = z.object({
  note: z.string().max(2000).optional(),
});
export type ApprovalDecisionRequest = z.infer<typeof ApprovalDecisionRequestSchema>;

// ── Platform policy (the thresholds the classifier reads) ────────────────────
// These are control-plane numbers, deliberately co-located with the classifier
// so portal-gating and SPA-preview never drift (§3).

/** LLM daily spend cap (USD) at/under which a grant is baseline. Tunable. */
export const BASELINE_DOLLARS_PER_DAY = 50;
/** App-data daily write/byte budgets at/under which a grant is baseline. */
export const BASELINE_WRITES_PER_DAY = 10_000;
export const BASELINE_BYTES_PER_DAY = 50_000_000;
/** Fetch-proxy daily request budget at/under which a grant is baseline. */
export const BASELINE_FETCH_REQUESTS_PER_DAY = 10_000;

/**
 * Models any app may request without approval. Anything else is elevated. The
 * curated set is exactly the priced catalog (`MODEL_PRICING`): a model the
 * platform has set a price for is one we're willing to serve, and conversely an
 * unpriced model can never be baseline — so the two can't drift, and the edge's
 * cost gate is never handed an unpriceable model on a baseline grant.
 */
export const CURATED_LLM_MODELS: readonly string[] = Object.keys(MODEL_PRICING);

/** Low-risk MCP servers any app may request. Empty ⇒ every MCP grant elevates. */
export const CURATED_MCP_ALLOWLIST: readonly string[] = [];

// ── The classifier ───────────────────────────────────────────────────────────

export interface ClassifyResult {
  /** Apply immediately within the PUT txn (as today). */
  baselineDeltas: Delta[];
  /** Bundle into one ApprovalRequest. */
  elevatedDeltas: Delta[];
  /** Max risk across the elevated deltas (queue sort); "low" when none. */
  risk: Risk;
}

/**
 * Budget privilege, ordered least→most permissive:
 *  - no grant at all (`llm`/`data` absent) ⇒ 0 — the edge 403s without the grant.
 *  - grant present, budget unset ⇒ `unsetMeans` (data/fetch: +∞; LLM uses
 *    asymmetric defaults in `classifyDeltas` — see below).
 *  - grant present, budget = n ⇒ n.
 * LLM cap deltas compare requested unset as +∞ (the portal cannot read
 * `EDGE_LLM_DEFAULT_DOLLARS_PER_DAY`, so a removed cap may land unlimited or
 * above baseline) against effective unset as `BASELINE_DOLLARS_PER_DAY` (what
 * the edge enforces when the install default is unchanged). Data/fetch still
 * treat unset as +∞ on both sides, so removing those caps is a privilege increase.
 */
function budgetPrivilege(
  hasGrant: boolean,
  v: number | undefined,
  unsetMeans: number = Number.POSITIVE_INFINITY,
): number {
  if (!hasGrant) return 0;
  return v ?? unsetMeans;
}

function diffArray(before: string[], after: string[]): { added: string[]; removed: string[] } {
  const b = new Set(before);
  const a = new Set(after);
  return {
    added: after.filter((x) => !b.has(x)),
    removed: before.filter((x) => !a.has(x)),
  };
}

/**
 * Canonical string key for a fetch proxy connection, used in delta paths and
 * diffing: `https://api.foo.com` (keyless), `https://api.foo.com→secret:name`
 * (secret-bound), or `https://api.foo.com→provider:ref` (provider-bound).
 * A secret-bound or provider-bound origin is strictly more sensitive,
 * so changing the bound credential is a remove+add of distinct keys.
 *
 * Exported because the delta paths this key form appears in are rendered and
 * matched by consumers beyond the classifier (the queue card, the portal's
 * filing stamps); the parse must stay the exact inverse.
 */
export function fetchOriginKey(c: {
  origin: string;
  connection?: string;
  provider?: string;
}): string {
  if (c.provider !== undefined) return `${c.origin}→provider:${c.provider}`;
  return c.connection ? `${c.origin}→secret:${c.connection}` : c.origin;
}
export function parseFetchOriginKey(key: string): {
  origin: string;
  connection?: string;
  provider?: string;
} {
  const p = key.indexOf("→provider:");
  if (p !== -1) {
    return { origin: key.slice(0, p), provider: key.slice(p + "→provider:".length) };
  }
  const i = key.indexOf("→secret:");
  return i === -1
    ? { origin: key }
    : { origin: key.slice(0, i), connection: key.slice(i + "→secret:".length) };
}

/**
 * Split a requested capability change into baseline (apply now) and elevated
 * (becomes a request) deltas. Two invariants (§3): reducing privilege is always
 * baseline; only increases gate. Each delta is classified independently.
 */
export function classifyChange(effective: unknown, requested: unknown): ClassifyResult {
  const eff = CapabilitiesSchema.parse(effective ?? {});
  const req = CapabilitiesSchema.parse(requested ?? {});

  const baseline: Delta[] = [];
  const elevated: Delta[] = [];

  // Risk rides inside the delta (it renders per-change in the approval queue),
  // and the request-level aggregate is the max across the elevated ones.
  const push = (delta: Delta & { risk: Risk }, isElevated: boolean) => {
    if (isElevated) elevated.push(delta);
    else baseline.push(delta);
  };

  // ── LLM models ──
  const effModels = eff.llm?.models ?? [];
  const reqModels = req.llm?.models ?? [];
  const models = diffArray(effModels, reqModels);
  for (const m of models.added) {
    const isElevated = !CURATED_LLM_MODELS.includes(m);
    push({ path: `llm.models[+${m}]`, to: m, risk: "med" }, isElevated);
  }
  for (const m of models.removed) {
    push({ path: `llm.models[-${m}]`, from: m, risk: "low" }, false);
  }

  // ── LLM spend budget (USD/day) ──
  const effDollars = eff.llm?.dollarsPerDay;
  const reqDollars = req.llm?.dollarsPerDay;
  if (effDollars !== reqDollars) {
    const reqPriv = budgetPrivilege(req.llm !== undefined, reqDollars);
    const effPriv = budgetPrivilege(eff.llm !== undefined, effDollars, BASELINE_DOLLARS_PER_DAY);
    const increase = reqPriv > effPriv;
    push(
      { path: "llm.dollarsPerDay", from: effDollars, to: reqDollars, risk: "med" },
      increase && reqPriv > BASELINE_DOLLARS_PER_DAY,
    );
  }

  // ── data: user store ── (scope itself is baseline; only budgets elevate)
  const effUser = eff.data?.user ?? false;
  const reqUser = req.data?.user ?? false;
  if (effUser !== reqUser) {
    push({ path: "data.user", from: effUser, to: reqUser, risk: "low" }, false);
  }

  // ── data: scope arrays ── (collections / shared keys are baseline grants)
  for (const [field, before, after] of [
    ["data.collections", eff.data?.collections ?? [], req.data?.collections ?? []],
    ["data.sharedRead", eff.data?.sharedRead ?? [], req.data?.sharedRead ?? []],
    ["data.sharedWrite", eff.data?.sharedWrite ?? [], req.data?.sharedWrite ?? []],
  ] as const) {
    const d = diffArray(before, after);
    for (const item of d.added) push({ path: `${field}[+${item}]`, to: item, risk: "low" }, false);
    for (const item of d.removed)
      push({ path: `${field}[-${item}]`, from: item, risk: "low" }, false);
  }

  // ── data: shared prefix grants (ADR-0042 decision 4) ──
  // Their OWN delta paths, distinct from the literal arrays above, because the
  // human reading the diff must never have to notice that one
  // `data.sharedWrite[+record:abc]` element means "one key" while one
  // `data.sharedWritePrefixes[+record:]` means "unboundedly many keys, chosen by
  // the app at runtime". Elevated on add — a human sees the unbounded grant once
  // — but risk `low`, the same tier as the literal grant: `shared` is
  // app-scoped and world-readable within the app's visibility gate by definition
  // (§3.3), so the prefix is not meaningfully more dangerous than the literals it
  // generalizes; `low` keeps the queue ordered by what actually matters.
  // Removal is a privilege reduction, so it is baseline like every other removal.
  for (const [field, before, after] of [
    [
      "data.sharedReadPrefixes",
      eff.data?.sharedReadPrefixes ?? [],
      req.data?.sharedReadPrefixes ?? [],
    ],
    [
      "data.sharedWritePrefixes",
      eff.data?.sharedWritePrefixes ?? [],
      req.data?.sharedWritePrefixes ?? [],
    ],
  ] as const) {
    const d = diffArray(before, after);
    for (const item of d.added) push({ path: `${field}[+${item}]`, to: item, risk: "low" }, true);
    for (const item of d.removed)
      push({ path: `${field}[-${item}]`, from: item, risk: "low" }, false);
  }

  // ── data: budgets ──
  for (const [field, effVal, reqVal, threshold] of [
    ["data.writesPerDay", eff.data?.writesPerDay, req.data?.writesPerDay, BASELINE_WRITES_PER_DAY],
    ["data.bytesPerDay", eff.data?.bytesPerDay, req.data?.bytesPerDay, BASELINE_BYTES_PER_DAY],
  ] as const) {
    if (effVal !== reqVal) {
      const reqPriv = budgetPrivilege(req.data !== undefined, reqVal);
      const increase = reqPriv > budgetPrivilege(eff.data !== undefined, effVal);
      push({ path: field, from: effVal, to: reqVal, risk: "med" }, increase && reqPriv > threshold);
    }
  }

  // ── mcp ──
  const mcp = diffArray(eff.mcp, req.mcp);
  for (const s of mcp.added) {
    const isElevated = !CURATED_MCP_ALLOWLIST.includes(s);
    push({ path: `mcp[+${s}]`, to: s, risk: "high" }, isElevated);
  }
  for (const s of mcp.removed) {
    push({ path: `mcp[-${s}]`, from: s, risk: "low" }, false);
  }

  // ── externalOrigins ── (any direct-CSP origin added is elevated)
  const origins = diffArray(eff.externalOrigins, req.externalOrigins);
  for (const o of origins.added) push({ path: `externalOrigins[+${o}]`, to: o, risk: "med" }, true);
  for (const o of origins.removed)
    push({ path: `externalOrigins[-${o}]`, from: o, risk: "low" }, false);

  // ── fetch.origins ── (proxied origins; keyless = med, secret/provider-bound = high)
  const effFetch = (eff.fetch?.origins ?? []).map(fetchOriginKey);
  const reqFetch = (req.fetch?.origins ?? []).map(fetchOriginKey);
  const fetchOrigins = diffArray(effFetch, reqFetch);
  for (const key of fetchOrigins.added) {
    const bound = parseFetchOriginKey(key);
    const credentialed = bound.connection !== undefined || bound.provider !== undefined;
    push({ path: `fetch.origins[+${key}]`, to: key, risk: credentialed ? "high" : "med" }, true);
  }
  for (const key of fetchOrigins.removed) {
    push({ path: `fetch.origins[-${key}]`, from: key, risk: "low" }, false);
  }

  // ── fetch.shim ── (serve-time ergonomics; never a privilege grant)
  const effShim = eff.fetch?.shim ?? false;
  const reqShim = req.fetch?.shim ?? false;
  if (effShim !== reqShim) {
    push({ path: "fetch.shim", from: effShim, to: reqShim, risk: "low" }, false);
  }

  // ── shim.connect ── (the connect helper's opt-in, same ergonomics tier)
  // Its own scalar path: the legacy-alias merge synchronizes only the FETCH
  // flag into `fetch.shim`, so a connect-only change would otherwise produce
  // no delta at all and silently fail to persist. The fetch sub-option keeps
  // the established `fetch.shim` path — one fact, one delta.
  const effConnect = eff.shim?.connect ?? false;
  const reqConnect = req.shim?.connect ?? false;
  if (effConnect !== reqConnect) {
    push({ path: "shim.connect", from: effConnect, to: reqConnect, risk: "low" }, false);
  }

  // ── fetch.requestsPerDay budget ──
  const effFetchReq = eff.fetch?.requestsPerDay;
  const reqFetchReq = req.fetch?.requestsPerDay;
  if (effFetchReq !== reqFetchReq) {
    const reqPriv = budgetPrivilege(req.fetch !== undefined, reqFetchReq);
    const increase = reqPriv > budgetPrivilege(eff.fetch !== undefined, effFetchReq);
    push(
      { path: "fetch.requestsPerDay", from: effFetchReq, to: reqFetchReq, risk: "med" },
      increase && reqPriv > BASELINE_FETCH_REQUESTS_PER_DAY,
    );
  }

  // ── offline (ADR-0035) ──
  // One scalar path carries grant, revoke and rescope. Taking the grant or
  // moving the scope elevates; giving it up is a privilege reduction, so it is
  // baseline like every other removal. `med`, not `high`: the marginal exposure
  // is the shell *rendering* after deauthorization — IndexedDB and the Cache API
  // already persist without any grant — and network-first documents mean an
  // online client always gets the live version.
  const effScope = eff.offline?.scope;
  const reqScope = req.offline?.scope;
  if (effScope !== reqScope) {
    push(
      { path: "offline.scope", from: effScope, to: reqScope, risk: "med" },
      reqScope !== undefined,
    );
  }

  return {
    baselineDeltas: baseline,
    elevatedDeltas: elevated,
    risk: maxRisk(elevated.map((d) => d.risk ?? "low")),
  };
}

export interface VisibilityChange {
  delta: Delta;
  elevated: boolean;
  risk: Risk;
}

/**
 * An app's whole visibility value: the mode plus, for `group`, the set of groups
 * that may open it. Both halves travel together because they are one decision
 * stored in one column pair, and classifying either alone gets it wrong — see
 * {@link visibilityLabel}.
 */
export interface VisibilityState {
  mode: VisibilityMode;
  /**
   * Optional so a `Visibility` union member passes straight in — `{ mode:
   * "internal" }` has no groups to name, and requiring an explicit `[]` at every
   * such call site buys nothing. Absent is read as empty.
   */
  groupIds?: string[];
}

/**
 * The canonical text form of a visibility value — `internal`, `password`,
 * `public`, or `group:<id>[,<id>…]` with the ids **sorted**.
 *
 * This is the same shorthand the `helix` CLI and the manifest already accept, so
 * it is not a new encoding; it is the repo's existing one, reused as the scalar
 * a {@link Delta} can carry.
 *
 * Sorting matters. Group membership is an any-of set, so order is meaningless —
 * sorting means re-selecting the same groups in a different order produces no
 * delta and no audit row. That is the opposite of the capability arrays, where
 * `snapshotConflicts` deliberately treats reordering as a change: there the
 * order is at least potentially meaningful, so counting it is the conservative
 * direction. Here it would be noise.
 */
export function visibilityLabel(state: VisibilityState): string {
  if (state.mode !== "group") return state.mode;
  return `group:${[...(state.groupIds ?? [])].sort().join(",")}`;
}

/**
 * Whether two visibility values are the same, compared as a **set** for `group`.
 *
 * Separate from {@link visibilityLabel} on purpose. The label is a display and
 * audit form, and using it as an equality key made a group id that *contains a
 * comma* collide with the pair it joins to: `["eng","prod"]` and `["eng,prod"]`
 * both label `group:eng,prod`, so switching an app between them compared equal,
 * produced no delta, and the route read that as a no-op — HTTP 200, no write, no
 * audit row, in both directions. A stringly-typed key over a delimiter the values
 * can contain is the bug; comparing the sets removes the class of it rather than
 * forbidding the character.
 */
function sameVisibility(a: VisibilityState, b: VisibilityState): boolean {
  if (a.mode !== b.mode) return false;
  if (a.mode !== "group") return true;
  const left = new Set(a.groupIds ?? []);
  const right = new Set(b.groupIds ?? []);
  return left.size === right.size && [...left].every((id) => right.has(id));
}

/**
 * Visibility lives in flat `apps` columns, not in `capabilities`, so it is
 * classified on its own. Only `→ public` elevates (high); every other move,
 * including `public → internal`, is baseline (§3).
 *
 * The operative rule is **"crossing the tenant boundary needs approval"**, not
 * "any widening needs approval". `group → internal` genuinely widens access
 * (one directory group → every authenticated principal) and is still baseline,
 * because `internal` *is* the platform's baseline trust level and the default
 * for a new app. What gates is exposure to people outside the directory. By the
 * same rule, **editing which groups may open a `group` app is baseline** — it
 * moves the population around inside the directory without ever leaving it.
 *
 * It compares whole visibility values, not just modes, and that is load-bearing
 * rather than tidy. While this took two `VisibilityMode`s, a `group → group` edit
 * that changed only the group set compared equal, returned `null`, and the caller
 * in `routes/apps.ts` treats `null` as a no-op — so changing which group could
 * open an app answered 200, wrote nothing, and audited nothing. That was invisible
 * while an app could hold only one group and the field was a free-text box; it is
 * the whole point of the feature now.
 *
 * The comparison is {@link sameVisibility} — a set test — and not equality of the
 * rendered label, which was the same bug one level down: an id containing the
 * label's `,` delimiter collided with the pair it joins to. The label is still
 * what the delta *carries*, because that is a human-facing diff.
 */
export function classifyVisibilityChange(
  from: VisibilityState,
  to: VisibilityState,
): VisibilityChange | null {
  if (sameVisibility(from, to)) return null;
  const fromLabel = visibilityLabel(from);
  const toLabel = visibilityLabel(to);
  const elevated = to.mode === "public";
  return {
    delta: { path: "visibility", from: fromLabel, to: toLabel, risk: elevated ? "high" : "low" },
    elevated,
    risk: elevated ? "high" : "low",
  };
}

// ── Applying deltas (route baseline write + approve elevated write) ───────────

/**
 * The closed set of array-valued delta paths `classifyChange` can emit, as a
 * regex **anchored on the field names** (ADR-0042 review finding 5). The
 * tempting `/^(.*)\[([+-])(.*)\]$/` is greedy on the field group, so it binds
 * at the LAST `[+`/`[-` — and an array ITEM containing `[` (legal in keys and
 * prefixes; free-form namespaces make it plausible) silently hijacked the
 * parse: `data.sharedReadPrefixes[-cfg[-v2]]` read as field
 * `data.sharedReadPrefixes[-cfg`, item `v2]`, and `applyArray`'s fall-through
 * no-op'd it — the owner revoked a grant and got a 200 with the grant intact.
 * Anchoring against the enumeration makes the split unambiguous (the field can
 * never absorb a `[`) without restricting what items may contain.
 */
const ARRAY_PATH =
  /^(mcp|externalOrigins|llm\.models|fetch\.origins|data\.(?:collections|sharedRead|sharedWrite|sharedReadPrefixes|sharedWritePrefixes))\[([+-])(.*)\]$/;

/**
 * Parse a membership delta path back into its parts — the read-side of the same
 * regex {@link applyDeltas} writes with. Exported so renderers (the approval
 * queue's chips) split paths with the exact grammar the classifier writes,
 * instead of forking a lookalike; items may contain `[`, which is the trap the
 * anchored field names exist for.
 */
export function parseArrayDeltaPath(
  path: string,
): { field: string; op: "+" | "-"; item: string } | null {
  const m = ARRAY_PATH.exec(path);
  if (!m) return null;
  return { field: m[1]!, op: m[2] as "+" | "-", item: m[3]! };
}

/**
 * Apply capability deltas to a capabilities object, returning a fresh parsed
 * copy. Visibility deltas are ignored here (the caller applies those to the
 * flat columns). Used to compute the baseline-applied capabilities on a PUT and
 * to apply the elevated bundle on approve.
 */
export function applyDeltas(capabilities: unknown, deltas: Delta[]): Capabilities {
  const next = CapabilitiesSchema.parse(JSON.parse(JSON.stringify(capabilities ?? {})) as unknown);

  for (const d of deltas) {
    const m = ARRAY_PATH.exec(d.path);
    if (m) {
      const [, field, op, item] = m as unknown as [string, string, "+" | "-", string];
      applyArray(next, field, op, item);
      continue;
    }
    applyScalar(next, d);
  }

  return CapabilitiesSchema.parse(next);
}

function applyArray(caps: Capabilities, field: string, op: "+" | "-", item: string): void {
  const add = (arr: string[]) =>
    op === "+" ? (arr.includes(item) ? arr : [...arr, item]) : arr.filter((x) => x !== item);
  switch (field) {
    case "mcp":
      caps.mcp = add(caps.mcp);
      return;
    case "externalOrigins":
      caps.externalOrigins = add(caps.externalOrigins);
      return;
    case "llm.models":
      caps.llm = { ...(caps.llm ?? { models: [] }), models: add(caps.llm?.models ?? []) };
      return;
    case "data.collections":
    case "data.sharedRead":
    case "data.sharedWrite":
    case "data.sharedReadPrefixes":
    case "data.sharedWritePrefixes": {
      const data = caps.data ?? {
        user: false,
        collections: [],
        sharedRead: [],
        sharedWrite: [],
        sharedReadPrefixes: [],
        sharedWritePrefixes: [],
      };
      const key = field.slice("data.".length) as
        | "collections"
        | "sharedRead"
        | "sharedWrite"
        | "sharedReadPrefixes"
        | "sharedWritePrefixes";
      caps.data = { ...data, [key]: add(data[key]) };
      return;
    }
    case "fetch.origins": {
      const fetch = ensureFetch(caps);
      const has = (o: FetchConnection) => fetchOriginKey(o) === item;
      const origins =
        op === "+"
          ? fetch.origins.some(has)
            ? fetch.origins
            : [...fetch.origins, parseFetchOriginKey(item)]
          : fetch.origins.filter((o) => !has(o));
      caps.fetch = { ...fetch, origins };
      return;
    }
    default:
      // Unreachable by construction — ARRAY_PATH is anchored on exactly the
      // case set above — but a silent fall-through here is the bug shape
      // finding 5 exploited (a delta that "applies" while doing nothing), so
      // the safety net fails loudly instead. Scalar paths keep their lenient
      // no-op: a pending request filed by an older build can carry a retired
      // scalar path, and applying nothing beats refusing to decide it forever
      // (ADR-0039 — requests never expire).
      throw new Error(`applyDeltas: unrecognized array field "${field}"`);
  }
}

function applyScalar(caps: Capabilities, d: Delta): void {
  switch (d.path) {
    case "llm.dollarsPerDay":
      caps.llm = { ...(caps.llm ?? { models: [] }), dollarsPerDay: d.to as number | undefined };
      return;
    case "data.user":
      caps.data = { ...ensureData(caps), user: Boolean(d.to) };
      return;
    case "data.writesPerDay":
      caps.data = { ...ensureData(caps), writesPerDay: d.to as number | undefined };
      return;
    case "data.bytesPerDay":
      caps.data = { ...ensureData(caps), bytesPerDay: d.to as number | undefined };
      return;
    case "fetch.shim": {
      const on = Boolean(d.to);
      caps.fetch = { ...ensureFetch(caps), shim: on };
      // CapabilitiesSchema's parse normalizes the legacy alias and the
      // first-class block into each other (OR-merge), so applying the delta to
      // the legacy boolean alone would let a stale canonical block merge the
      // old value back on the re-parse below — a revoked shim that stayed on.
      // Write both views, then let the parse confirm them.
      if (on || caps.shim) {
        caps.shim = { fetch: on, connect: caps.shim?.connect ?? false };
      }
      return;
    }
    case "shim.connect": {
      const on = Boolean(d.to);
      // The parse has already synchronized the fetch view (the transform writes
      // both positions), so the block is rebuilt with the merged fetch flag.
      caps.shim = { fetch: caps.shim?.fetch ?? caps.fetch?.shim ?? false, connect: on };
      return;
    }
    case "fetch.requestsPerDay":
      caps.fetch = { ...ensureFetch(caps), requestsPerDay: d.to as number | undefined };
      return;
    case "offline.scope":
      // `to` absent ⇒ the grant was given up; drop the block entirely rather
      // than leaving an `offline: {}` that would fail the schema's refinement.
      if (typeof d.to === "string") caps.offline = { scope: d.to };
      else delete caps.offline;
      return;
    default:
      return;
  }
}

function ensureData(caps: Capabilities) {
  return (
    caps.data ?? {
      user: false,
      collections: [],
      sharedRead: [],
      sharedWrite: [],
      sharedReadPrefixes: [],
      sharedWritePrefixes: [],
    }
  );
}

function ensureFetch(caps: Capabilities) {
  return caps.fetch ?? { shim: false, origins: [] };
}

// ── Conflict detection (optimistic concurrency, §5) ──────────────────────────

const AREAS = ["llm", "data", "mcp", "externalOrigins", "fetch", "offline", "visibility"] as const;
type Area = (typeof AREAS)[number];

function deltaArea(path: string): Area {
  if (path === "visibility") return "visibility";
  if (path.startsWith("llm")) return "llm";
  if (path.startsWith("data")) return "data";
  if (path.startsWith("mcp")) return "mcp";
  // The shim block's own sub-option paths (`shim.connect`) area with the fetch
  // ergonomics they serve — the block stays at the fetch-shim classification.
  if (path.startsWith("fetch") || path.startsWith("shim")) return "fetch";
  if (path.startsWith("offline")) return "offline";
  return "externalOrigins";
}

/** The distinct policy areas a set of deltas touches. */
export function touchedAreas(deltas: Delta[]): Area[] {
  const set = new Set<Area>();
  for (const d of deltas) set.add(deltaArea(d.path));
  return AREAS.filter((a) => set.has(a));
}

/** A decided sibling request, newest-first, as fed to {@link summarizePriorDecisions}. */
export interface PriorDecisionRow {
  status: ApprovalStatus;
  deltas: Delta[];
  decisionNote: string | null;
  decidedBy: string | null;
  decidedAt: string;
}

/**
 * Summarize a pending request's decided siblings on the *same app* for the admin
 * queue (issue #26). Matching is deliberately boring: a `denied` sibling sharing
 * an exact delta `path` is the same grant (loud); one merely touching an
 * overlapping policy area is related (quiet). Both counts are `denied`-only —
 * approvals/withdrawals/needs_changes are history, surfaced via `last`, not the
 * flag. Returns `undefined` when there are no prior decisions, so the field is
 * omitted and a first-time request keeps its original wire shape.
 */
export function summarizePriorDecisions(
  current: Delta[],
  prior: PriorDecisionRow[],
): PriorDecisions | undefined {
  if (prior.length === 0) return undefined;

  const currentPaths = new Set(current.map((d) => d.path));
  const currentAreas = new Set(current.map((d) => deltaArea(d.path)));

  let deniedSameGrant = 0;
  let deniedSameArea = 0;
  for (const row of prior) {
    if (row.status !== "denied") continue;
    if (row.deltas.some((d) => currentPaths.has(d.path))) deniedSameGrant++;
    if (row.deltas.some((d) => currentAreas.has(deltaArea(d.path)))) deniedSameArea++;
  }

  // `prior` is newest-first (the caller orders by decidedAt desc), so the head
  // is the most recent decision.
  const head = prior[0]!;
  return {
    total: prior.length,
    deniedSameArea,
    deniedSameGrant,
    last: {
      status: head.status,
      note: head.decisionNote,
      decidedBy: head.decidedBy,
      decidedAt: head.decidedAt,
    },
  };
}

/**
 * Snapshot the effective value of each touched area at request time. Stored as
 * `baseSnapshot`; compared at approve time to detect a value that moved
 * underneath the open request (a baseline write or another approval).
 */
export function captureSnapshot(
  effective: unknown,
  visibility: VisibilityState,
  areas: Area[],
): Record<string, unknown> {
  const caps = CapabilitiesSchema.parse(effective ?? {});
  const snap: Record<string, unknown> = {};
  for (const area of areas) {
    // The visibility area snapshots the whole {@link visibilityLabel}, not the
    // bare mode: a `group` app whose group set moved under an open request has
    // changed in exactly the way this check exists to catch, and a mode-only
    // snapshot compared equal through it.
    snap[area] =
      area === "visibility"
        ? visibilityLabel(visibility)
        : (caps[area as keyof Capabilities] ?? null);
  }
  return snap;
}

/**
 * Serialize a snapshot area with object keys sorted, recursively.
 *
 * The plain `JSON.stringify` this replaces is **key-order sensitive**, and the
 * two sides of the comparison genuinely carry different orders: the stored
 * `baseSnapshot` is a jsonb column, and Postgres re-orders object keys
 * canonically at rest (by key length, then bytewise), while the approve-time
 * re-derivation goes through `CapabilitiesSchema.parse`, and zod emits keys in
 * **shape** order. For most areas the two orders coincide (llm: `models` <
 * `dollarsPerDay`; fetch: `shim` < `origins` < `requestsPerDay`), which is why
 * this slept — but the `data` area's shape order (`user, collections,
 * sharedRead, sharedWrite, …`) differs from its jsonb order (`user,
 * sharedRead, collections, sharedWrite, …`), so every data-area approve read a
 * value that never moved as "changed" and auto-bounced to `needs_changes`. The
 * first data-area elevated grant that anyone actually approved was a
 * `sharedWritePrefixes` prefix (ADR-0042), which is what surfaced it.
 *
 * **Array order stays significant** — capability arrays are ordered grants
 * where reordering is a real change — so only object keys are sorted.
 */
function canonicalSnapshotJson(value: unknown): string {
  return JSON.stringify(value, (_key, v) => {
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      return Object.fromEntries(
        Object.entries(v as Record<string, unknown>).sort(([a], [b]) =>
          a < b ? -1 : a > b ? 1 : 0,
        ),
      );
    }
    return v;
  });
}

/**
 * The stored half of one snapshot area, normalized the way the approve-time
 * re-derivation is (ADR-0042 review finding 2).
 *
 * `captureSnapshot` parses through `CapabilitiesSchema`, so the fresh side
 * carries every field the schema currently defaults. The STORED side is a jsonb
 * column written when the request was filed — possibly by an older build, before
 * a field existed — so a plain comparison reads a defaulted-but-unchanged field
 * as a key-SET difference and every approve of a request that spans a deploy
 * auto-bounces to `needs_changes`. (This is the same class as the key-ORDER bug
 * {@link canonicalSnapshotJson} fixed: a representation difference read as a
 * moved value.) Re-parsing the stored area through the same schema erases the
 * difference for free, and keeps doing so for the NEXT field added to any
 * capability — which is the actual regression test: a snapshot missing a field
 * the schema now defaults must not conflict.
 *
 * `visibility` is exempt (it is the label, not a capabilities area), and a value
 * that will not parse — `null` areas, or a snapshot older than the field's whole
 * area — falls back to the raw value, preserving the pre-normalization
 * comparison rather than inventing a conflict.
 */
function storedSnapshotArea(key: string, value: unknown): unknown {
  if (key === "visibility" || value === null || typeof value !== "object") return value;
  const parsed = CapabilitiesSchema.safeParse({ [key]: value });
  return parsed.success ? parsed.data[key as keyof typeof parsed.data] : value;
}

/**
 * True if any snapshotted area no longer matches current effective state — the
 * diff is stale and approval must bounce to `needs_changes` rather than clobber.
 * Array reordering counts as a change (conservative, safe direction); object
 * key order does not (see {@link canonicalSnapshotJson}), and neither do
 * schema-defaulted fields the stored snapshot predates (see
 * {@link storedSnapshotArea}).
 */
export function snapshotConflicts(
  baseSnapshot: unknown,
  effective: unknown,
  visibility: VisibilityState,
): boolean {
  if (baseSnapshot === null || typeof baseSnapshot !== "object") return false;
  const snap = baseSnapshot as Record<string, unknown>;
  const current = captureSnapshot(effective, visibility, Object.keys(snap) as Area[]);
  for (const key of Object.keys(snap)) {
    if (
      canonicalSnapshotJson(storedSnapshotArea(key, snap[key])) !==
      canonicalSnapshotJson(current[key])
    ) {
      return true;
    }
  }
  return false;
}
