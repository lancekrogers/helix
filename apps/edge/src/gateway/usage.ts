import { type Pool } from "pg";

import { type Env, type GatewayOutcome, type PrincipalKind } from "@azx-pbc/shared";
import {
  ATTR_APP_ID,
  ATTR_CAPABILITY,
  ATTR_OUTCOME,
  ATTR_REASON,
  ATTR_USAGE_BASIS,
  capTargetPath,
  TARGET_PATH_MAX,
  type AdmissionDenialReason,
  type CutChargeBasis,
} from "@azx-pbc/shared/telemetry";

import { USER_EMAIL_MAX, USER_NAME_MAX, truncate } from "../auth/identity.js";
import { createEdgePool, type EdgePoolOpts } from "../db/pool.js";
import { withPartition } from "../db/partition.js";
import { instruments } from "../telemetry.js";

/** Default TTL for cached platform LLM spend reads (per edge replica). */
export const PLATFORM_SPEND_CACHE_MS = 5_000;

export interface PgUsageStoreOpts extends EdgePoolOpts {
  /** Platform spend cache TTL; `0` disables caching (tests). */
  platformCacheMs?: number;
}

/** Boot self-test and integration tests share this catalog query (ADR-0002). */
export const PLATFORM_SPEND_CHECK_SQL = `
SELECT
  p.proname = 'platform_llm_spend_micro_usd' AS fn_name_ok,
  p.prosecdef AS security_definer,
  EXISTS (
    SELECT 1 FROM unnest(COALESCE(p.proconfig, ARRAY[]::text[])) AS cfg
    WHERE cfg LIKE 'search_path=%'
  ) AS search_path_pinned,
  pg_get_userbyid(p.proowner) AS function_owner,
  pol.policyname = 'gateway_calls_owner_read' AS policy_name_ok,
  pol.cmd = 'SELECT' AS policy_cmd_ok,
  pol.roles @> ARRAY[pg_get_userbyid(p.proowner)]::name[] AS policy_admits_owner
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = 'public'
LEFT JOIN pg_policies pol
  ON pol.tablename = 'gateway_calls'
 AND pol.policyname = 'gateway_calls_owner_read'
WHERE p.proname = 'platform_llm_spend_micro_usd'
  AND pg_get_function_identity_arguments(p.oid) = 'p_env text'
`;

export type PlatformSpendCheck =
  | { status: "ok" }
  | { status: "misconfigured"; problem: string }
  | { status: "unreachable"; error: unknown };

export type PlatformSpendCheckRow = {
  fn_name_ok: boolean;
  security_definer: boolean;
  search_path_pinned: boolean;
  policy_name_ok: boolean;
  policy_cmd_ok: boolean;
  policy_admits_owner: boolean;
};

export function classifyPlatformSpendCheck(
  rows: PlatformSpendCheckRow[],
): Exclude<PlatformSpendCheck, { status: "unreachable" }> {
  const row = rows[0];
  if (!row?.fn_name_ok) {
    return { status: "misconfigured", problem: "platform_llm_spend_micro_usd is missing" };
  }
  if (!row.security_definer) {
    return {
      status: "misconfigured",
      problem: "platform_llm_spend_micro_usd is not SECURITY DEFINER",
    };
  }
  if (!row.search_path_pinned) {
    return {
      status: "misconfigured",
      problem: "platform_llm_spend_micro_usd does not pin search_path",
    };
  }
  if (!row.policy_name_ok || !row.policy_cmd_ok || !row.policy_admits_owner) {
    return {
      status: "misconfigured",
      problem: "gateway_calls_owner_read does not admit the function owner",
    };
  }
  return { status: "ok" };
}

function postgresErrorCode(err: unknown): string | undefined {
  if (err && typeof err === "object" && "code" in err) {
    const code = (err as { code?: unknown }).code;
    return typeof code === "string" ? code : undefined;
  }
  return undefined;
}

/**
 * The gateway call ledger (architecture §6.1/§6.3, §8) — metering + audit and
 * the source of truth for per-app daily token budgets. Lives in the portal-
 * migrated `gateway_calls` table, accessed with hand-written SQL (no ORM in the
 * edge — project plan §1).
 *
 * This is the one place the edge **writes** product data. The widening from the
 * edge's otherwise read-only posture is deliberate and narrow: INSERT a row per
 * call, and SUM today's tokens to admit or block the next one. No secrets, no
 * registry writes.
 *
 * Every access runs through `withPartition` so the `gateway_calls_edge_partition`
 * RLS policy (ADR-0002) scopes it to the request's app: the per-app budget SUMs
 * and the metering INSERT can only ever see / write this app's rows, and a path
 * that forgot the `app.app_id` GUC matches zero rows / fails the WITH CHECK
 * (fail-closed) rather than crossing tenants. Metering is per-app, so only
 * `app.app_id` is set (no `app.user_oid`). The txn adds a round-trip to the
 * metering hot path — an accepted cost for the fail-closed backstop.
 */

// `GatewayOutcome` is imported from `@azx-pbc/shared`, not redeclared here. A
// local union drifted from the shared one once already (`conflict`), and since
// the portal parses every ledger row through `GatewayCallSchema`, the drift
// turned each app-data 412 into a 500 on the audit route. Re-export so existing
// importers of this module are unaffected.
export type { GatewayOutcome };

export interface GatewayCallRecord {
  appId: string;
  /** Partition tier (dev-mode design §5.1) — keeps budgets/usage per-env. */
  env: Env;
  userOid: string;
  /**
   * The display half of the caller (`MeterIdentity` in auth/gate.ts, which this
   * shape is structurally compatible with so `...meterIdentity(caller)` spreads
   * straight in). Rendered by the portal, never compared. Null for `anon`,
   * shared-password and dev-token principals.
   */
  userName: string | null;
  userEmail: string | null;
  /** Which kind of principal this was — recorded, never inferred from `userOid`. */
  userKind: PrincipalKind | null;
  /** Capability invoked — `llm` in M4. */
  capability: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  /** Cache-aware input accounting; defaults to 0 (caching not enabled yet). */
  cacheReadInputTokens?: number;
  cacheCreationInputTokens?: number;
  /** Frozen as-charged cost in micro-USD (1e-6 USD); defaults to 0. */
  costMicroUsd?: number;
  outcome: GatewayOutcome;
  /** Upstream round-trip latency in ms; defaults to 0 when not measured. */
  durationMs?: number;
  /** Upstream/egress HTTP status (fetch); null/omitted for streamed llm. */
  statusCode?: number | null;
  /** LLM stop reason; null/omitted for non-LLM. */
  stopReason?: string | null;
  /** Short upstream error string; null/omitted on success. */
  errorDetail?: string | null;
  /**
   * Request path of a proxied `fetch` call, **query string excluded**; omitted
   * for every other capability. Truncated to {@link PATH_MAX} by
   * {@link fetchPathOf} — see the note there.
   */
  path?: string | null;
  /** HTTP method of a proxied `fetch` call; omitted for other capabilities. */
  method?: string | null;
}

/** Max length of the `errorDetail` ledger string, before the ellipsis. */
export const ERROR_DETAIL_MAX = 300;

/**
 * Max length of the `path` ledger column, before the ellipsis.
 *
 * Re-exported from `@azx-pbc/shared/telemetry` rather than defined here: egress
 * records the same value as a span attribute and cannot import from `apps/edge`,
 * so the number lives where both planes can reach it.
 */
export const PATH_MAX = TARGET_PATH_MAX;

/*
 * The captured-label caps (`USER_NAME_MAX`, `USER_EMAIL_MAX`) live in
 * `../auth/identity.js`, which is also where they are applied at capture time.
 *
 * Note the threat differs from every other cap in this file, so don't read
 * ADR-0021's reasoning onto them: `path` and `model` are **app**-controlled, and
 * their caps bound what untrusted hosted code can write into an append-only
 * table. The labels are **directory**-controlled — they arrive in a signed ID
 * token the hosted app cannot influence. That cap is row-size hygiene, not a
 * containment boundary.
 *
 * Re-applying it here anyway is deliberate and idempotent: `clampRecord` is
 * shared by `PgUsageStore` and the test fake, so a cap enforced only at capture
 * would be invisible to every unit test of the store.
 */

/**
 * Max length of the `model` ledger column, before the ellipsis.
 *
 * Deliberately **not** `ERROR_DETAIL_MAX`: `model` is a WHERE predicate, not free
 * text. `dataWritesToday` matches it with `model = ANY($3)` against
 * `DATA_WRITE_VERBS`, so the cap has to sit well clear of every real value or it
 * would silently stop matching — the longest verb is 17 chars, the longest model
 * id ~25, and a manifest origin is short. 200 leaves two orders of headroom over
 * that floor while still bounding what an app can write: for `fetch` this column
 * carries `target.origin`, whose only other bound is Node's `maxHeaderSize`.
 * The column is plain TEXT (no `@db.VarChar`), so this is the only bound there is.
 */
export const MODEL_MAX = 200;

/**
 * Render a proxied call's pathname for the `path` ledger column.
 *
 * Two things this is load-bearing for:
 *
 *  - **The query string never arrives here.** Callers pass `URL.pathname`, so
 *    the target's query is gone before this point — that is where credentials
 *    are conventionally placed (`?api_key=`, a SAS `?sig=`), and the request-log
 *    serializer draws the same line (`redactFetchTarget` in
 *    `@azx-pbc/shared/logging`).
 *
 *    **This does not make the result credential-free**, and nothing should be
 *    written as though it does. Plenty of APIs put the secret in a path segment
 *    (Telegram `/bot<TOKEN>/…`, Slack webhooks `/services/T…/B…/<secret>`). No
 *    heuristic is applied, deliberately: a token segment and a REST resource id
 *    are the same shape, so any entropy test that catches `/bot<TOKEN>` also
 *    eats `/customers/<uuid>/orders` — the value this column exists to capture.
 *    Bounding is the mitigation, not detection, and retention is the real fix
 *    (ADR-0021). The ledger is the stricter store of the two: log lines age out,
 *    ledger rows have no DELETE grant for any role.
 *  - **The length is capped.** The path is attacker-controlled — it is whatever
 *    the hosted app put in the URL — and `gateway_calls` is append-only with no
 *    DELETE grant for any role and no pruning job, so an app writing multi-KB
 *    paths would be unfixable after the fact.
 */
export function fetchPathOf(pathname: string): string {
  return capTargetPath(pathname);
}

/** How far up the `cause` chain to walk. Deep enough for undici's wrapping. */
const ERROR_CAUSE_DEPTH = 4;

/**
 * Render a thrown value for the `errorDetail` ledger column (internal-only, not
 * app-facing), following the `cause` chain.
 *
 * Recording `err.message` alone loses the only part that says *what went wrong
 * at the wire*. `EgressProviderError` is thrown as
 * `new EgressProviderError("egress request failed", { cause: err })`
 * (`egressProvider.ts`), so a DNS failure and a refused connection both land in
 * the ledger as the identical, undiagnosable string "egress request failed" —
 * the `ENOTFOUND` / `ECONNREFUSED` that distinguishes them sits one level down
 * in the cause and used to be dropped here. That cost a live incident four
 * diagnostic steps (an `az containerapp exec` into the running edge replica) to
 * recover a code the ledger already had in hand.
 *
 * So: walk the chain, and append each level's `code` when it carries one. A
 * transport failure now records as
 * `egress request failed: getaddrinfo ENOTFOUND <host> [ENOTFOUND]`.
 */
export function errorDetailOf(err: unknown): string {
  const parts: string[] = [];
  let cur: unknown = err;

  for (let depth = 0; depth < ERROR_CAUSE_DEPTH && cur != null; depth += 1) {
    if (!(cur instanceof Error)) {
      parts.push(String(cur));
      break;
    }
    // `code` is the Node/undici system-error discriminator (ENOTFOUND,
    // ECONNREFUSED, UND_ERR_*). Not on the Error type, hence the narrowing.
    const code = (cur as Error & { code?: unknown }).code;
    parts.push(typeof code === "string" ? `${cur.message} [${code}]` : cur.message);
    cur = cur.cause;
  }

  return truncate(parts.join(": "), ERROR_DETAIL_MAX);
}

/**
 * Clamp every app-influenced string on a ledger record to its column budget.
 *
 * Applied by **both** `PgUsageStore` and the test fake, not inside the SQL layer:
 * a cap that lives only in the Pg store is unreachable from every unit test, and
 * the fake would then disagree with the real store about what it stores — the
 * same class of drift the shared `fetchRequestsToday` predicate exists to avoid.
 *
 * `path` normally arrives pre-capped via {@link fetchPathOf}; re-clamping is
 * idempotent (the same constant) and closes the gap for any future call site
 * that forgets. `model` and `errorDetail` are the ones that actually needed it:
 * both are built by call sites from `target.origin`, whose only bound is Node's
 * `maxHeaderSize` — a 3.6 KB host produced a ~7 KB row before this existed.
 */
export function clampRecord(call: GatewayCallRecord): GatewayCallRecord {
  return {
    ...call,
    model: truncate(call.model, MODEL_MAX),
    userName: call.userName === null ? null : truncate(call.userName, USER_NAME_MAX),
    userEmail: call.userEmail === null ? null : truncate(call.userEmail, USER_EMAIL_MAX),
    ...(call.path != null ? { path: truncate(call.path, PATH_MAX) } : {}),
    ...(call.errorDetail != null
      ? { errorDetail: truncate(call.errorDetail, ERROR_DETAIL_MAX) }
      : {}),
  };
}

/** The two LLM spend windows the gate checks, in micro-USD (1e-6 USD). */
export interface LlmSpend {
  /** Spend since local-midnight — the daily cost cap. */
  todayMicro: number;
  /** Spend in the trailing rolling hour — the burst/availability cap. */
  hourMicro: number;
}

export interface UsageStore {
  /**
   * Frozen LLM spend (micro-USD) for this app in the day + rolling-hour windows,
   * summed from the `costMicroUsd` ledger column. Backs the per-app USD budget
   * gate (`llm.ts`).
   */
  llmSpendMicroUsd(appId: string, env: Env): Promise<LlmSpend>;
  /**
   * Platform-wide LLM spend (micro-USD) for one env, from the definer aggregate.
   * Cached per store instance; throws when the read fails.
   */
  platformLlmSpendMicroUsd(env: Env): Promise<LlmSpend>;
  /**
   * Count of successful app-data **write** calls today (app-data design §7) —
   * the per-app `writesPerDay` budget window. Writes are the put/append verbs
   * (`user.put`, `collection.append`, `shared.put`); reads and quota-blocks
   * don't count.
   */
  dataWritesToday(appId: string, env: Env): Promise<number>;
  /**
   * Count of admitted fetch-proxy calls today (fetch-proxy design §7) — the
   * per-app `requestsPerDay` budget window. "Admitted" means everything we
   * recorded except **the platform's own pre-egress refusals** (`quota_blocked`
   * and `forbidden`), so a flood of failing calls still counts against the cap.
   *
   * The budget prices work done on the app's behalf at the egress boundary: an
   * `error` or `refusal` row dialled egress, a `forbidden` row (allowlist
   * denial) mints no instruction and costs no third party. Counting denials
   * would also be pointless as a bound — the allowlist check returns *before*
   * this gate, so a denial loop never reaches it and writes rows either way;
   * counting them would only starve the app's legitimate traffic.
   *
   * `connection_required` is deliberately **counted** — it consumes
   * budget. It is not a policy refusal (the separation from
   * `refusal` is the label's whole point), but the exclusion above is about
   * *where* the refusal happens, not why: this one happens at egress, after
   * the call was authorized, an instruction minted, and egress did real work
   * (verify, provider-cache read, connection resolution). Excluding it would
   * leave a not-connected retry loop — which the allowlist denial throttle
   * cannot bound, because the origin IS granted — an unmetered ride on the
   * egress hop. The audit separation lives in the
   * `outcome` label itself, not in the budget arithmetic.
   */
  fetchRequestsToday(appId: string, env: Env): Promise<number>;
  /** Append one call to the ledger. */
  record(call: GatewayCallRecord): Promise<void>;
  close(): Promise<void>;
}

/** The `model` values recorded for app-data write verbs (see dataWritesToday). */
export const DATA_WRITE_VERBS = ["user.put", "collection.append", "shared.put"] as const;

export class PgUsageStore implements UsageStore {
  #pool: Pool;
  #platformCacheMs: number;
  #platformCache = new Map<Env, { at: number; value: LlmSpend }>();
  #platformInflight = new Map<Env, Promise<LlmSpend>>();

  constructor(databaseUrl: string, opts: PgUsageStoreOpts = {}) {
    // Spread, don't re-list — see the note in auth/sessions.ts.
    this.#pool = createEdgePool(databaseUrl, {
      ...opts,
      max: opts.max ?? 10,
      label: opts.label ?? "usage",
    });
    this.#platformCacheMs = opts.platformCacheMs ?? PLATFORM_SPEND_CACHE_MS;
  }

  peekPlatformSpend(env: Env): LlmSpend | null {
    return this.#platformCache.get(env)?.value ?? null;
  }

  async platformLlmSpendMicroUsd(env: Env): Promise<LlmSpend> {
    if (this.#platformCacheMs > 0) {
      const hit = this.#platformCache.get(env);
      if (hit && Date.now() - hit.at < this.#platformCacheMs) return hit.value;
    }
    let read = this.#platformInflight.get(env);
    if (!read) {
      read = this.#readPlatform(env)
        .then((value) => {
          if (this.#platformCacheMs > 0) {
            this.#platformCache.set(env, { at: Date.now(), value });
          }
          return value;
        })
        .finally(() => this.#platformInflight.delete(env));
      this.#platformInflight.set(env, read);
    }
    return read;
  }

  async #readPlatform(env: Env): Promise<LlmSpend> {
    // Straight on the pool, not withPartition: the function takes the env itself, and a
    // partition would set an app GUC that means nothing here.
    const result = await this.#pool.query(
      "SELECT today, hour FROM platform_llm_spend_micro_usd($1)",
      [env],
    );
    const row = result.rows[0] as { today: string | number; hour: string | number } | undefined;
    return { todayMicro: row ? Number(row.today) : 0, hourMicro: row ? Number(row.hour) : 0 };
  }

  async checkPlatformSpendFunction(): Promise<PlatformSpendCheck> {
    try {
      const catalog = await this.#pool.query(PLATFORM_SPEND_CHECK_SQL);
      const classified = classifyPlatformSpendCheck(catalog.rows as PlatformSpendCheckRow[]);
      if (classified.status === "misconfigured") return classified;
      await this.#pool.query(`SELECT * FROM platform_llm_spend_micro_usd('prod')`);
      return { status: "ok" };
    } catch (err) {
      const code = postgresErrorCode(err);
      if (code === "42501" || code === "42883") {
        return {
          status: "misconfigured",
          problem:
            code === "42501"
              ? "helix_edge cannot execute platform_llm_spend_micro_usd"
              : "platform_llm_spend_micro_usd is not callable",
        };
      }
      return { status: "unreachable", error: err };
    }
  }

  async llmSpendMicroUsd(appId: string, env: Env): Promise<LlmSpend> {
    // One index scan over (appId, env, createdAt), two FILTERed sums. The outer
    // filter is day-start minus an hour so the rolling-hour window stays
    // correct across the midnight boundary (its rows can predate today). Day
    // boundary is server-local-midnight via date_trunc on now() (architecture
    // §6.3). costMicroUsd is non-null (DEFAULT 0). The env predicate is redundant
    // with the env-literal RLS policy (which already scopes the role to one tier)
    // but is kept explicit so the query rides the (appId, env, createdAt) index.
    return withPartition(this.#pool, appId, null, env, async (client) => {
      const result = await client.query(
        `SELECT
           COALESCE(SUM("costMicroUsd") FILTER (WHERE "createdAt" >= date_trunc('day', now())), 0)::bigint AS today,
           COALESCE(SUM("costMicroUsd") FILTER (WHERE "createdAt" >= now() - interval '1 hour'), 0)::bigint AS hour
         FROM gateway_calls
         WHERE "appId" = $1 AND env = $2 AND capability = 'llm'
           AND "createdAt" >= date_trunc('day', now()) - interval '1 hour'`,
        [appId, env],
      );
      // SUM(::bigint) comes back as a string from pg; Number is safe well below
      // 2^53 for any realistic daily micro-USD total (1e6 = $1).
      const row = result.rows[0] as { today: string | number; hour: string | number } | undefined;
      return { todayMicro: row ? Number(row.today) : 0, hourMicro: row ? Number(row.hour) : 0 };
    });
  }

  async dataWritesToday(appId: string, env: Env): Promise<number> {
    return withPartition(this.#pool, appId, null, env, async (client) => {
      const result = await client.query(
        `SELECT COUNT(*)::int AS n
         FROM gateway_calls
         WHERE "appId" = $1 AND env = $2 AND capability = 'data' AND outcome = 'ok'
           AND model = ANY($3) AND "createdAt" >= date_trunc('day', now())`,
        [appId, env, DATA_WRITE_VERBS],
      );
      const row = result.rows[0] as { n: string | number } | undefined;
      return row ? Number(row.n) : 0;
    });
  }

  async fetchRequestsToday(appId: string, env: Env): Promise<number> {
    return withPartition(this.#pool, appId, null, env, async (client) => {
      const result = await client.query(
        // `connection_required` stays counted on purpose — it is an egress
        // outcome, not a pre-egress refusal of ours. See the interface
        // docblock above for the full reasoning.
        `SELECT COUNT(*)::int AS n
         FROM gateway_calls
         WHERE "appId" = $1 AND env = $2 AND capability = 'fetch'
           AND outcome NOT IN ('quota_blocked', 'forbidden')
           AND "createdAt" >= date_trunc('day', now())`,
        [appId, env],
      );
      const row = result.rows[0] as { n: string | number } | undefined;
      return row ? Number(row.n) : 0;
    });
  }

  async record(raw: GatewayCallRecord): Promise<void> {
    const call = clampRecord(raw);
    await withPartition(this.#pool, call.appId, null, call.env, async (client) => {
      await client.query(
        // Prisma's @default(uuid()) is client-side, so the raw INSERT supplies
        // the id itself (gen_random_uuid() — built into Postgres). `env` is set
        // explicitly (not left to the column default) so a `dev` row satisfies the
        // helix_dev WITH CHECK (env='dev') — the default 'prod' would fail it.
        // Optional metering columns fall back to their column defaults / NULL.
        `INSERT INTO gateway_calls
           (id, "appId", env, "userOid", "userName", "userEmail", "userKind", capability, model,
            "inputTokens", "outputTokens",
            "cacheReadInputTokens", "cacheCreationInputTokens", "costMicroUsd", outcome,
            "durationMs", "statusCode", "stopReason", "errorDetail", path, method)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                 $16, $17, $18, $19, $20)`,
        [
          call.appId,
          call.env,
          call.userOid,
          call.userName,
          call.userEmail,
          call.userKind,
          call.capability,
          call.model,
          call.inputTokens,
          call.outputTokens,
          call.cacheReadInputTokens ?? 0,
          call.cacheCreationInputTokens ?? 0,
          call.costMicroUsd ?? 0,
          call.outcome,
          call.durationMs ?? 0,
          call.statusCode ?? null,
          call.stopReason ?? null,
          call.errorDetail ?? null,
          call.path ?? null,
          call.method ?? null,
        ],
      );
    });
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }
}

export function meterAdmissionDenied(call: {
  appId: string;
  capability: string;
  reason: AdmissionDenialReason;
}): void {
  instruments().gatewayAdmissionDenied.add(1, {
    [ATTR_APP_ID]: call.appId,
    [ATTR_CAPABILITY]: call.capability,
    [ATTR_REASON]: call.reason,
  });
}

/**
 * Record the operational metrics for one gateway terminal (ADR-0037 decision 8).
 *
 * **Beside the ledger write, never inside `PgUsageStore.record`.** Three
 * reasons, in order of how much they matter:
 *
 *  1. `record` can fail, and every call site swallows that with a `.catch`. A
 *     DB blip must not also blind the operational counter — those are exactly
 *     the minutes an operator is looking at it.
 *  2. `PgUsageStore` is one of two `UsageStore` implementations (the other is
 *     the test fake). Metrics placed inside it would be invisible to every unit
 *     test and absent from the dev gateway.
 *  3. ADR-0037 decision 9 says this counter is **never reconciled against the
 *     ledger, never used to bill, and never presented as the authority.**
 *     Keeping the two adjacent-but-independent makes that structural rather
 *     than a comment: a dropped span costs a data point, a dropped ledger row
 *     costs money and an audit trail.
 *
 * They still share a call site, so the `outcome` vocabulary cannot drift.
 */
export function meterGatewayCall(call: {
  appId: string;
  capability: string;
  outcome: GatewayOutcome;
  durationMs?: number;
}): void {
  const { gatewayCalls, gatewayDuration } = instruments();

  gatewayCalls.add(1, {
    [ATTR_CAPABILITY]: call.capability,
    [ATTR_OUTCOME]: call.outcome,
    [ATTR_APP_ID]: call.appId,
  });

  // **Only when the call actually measured a round trip.** `quota_blocked` and
  // `forbidden` are refused before anything is dialled, and the app-data path
  // does not time itself — recording `0` for those would drag every percentile
  // toward zero and make the histogram say the platform is fast when what it
  // really did was refuse. That is the same failure ADR-0037 decision 5 names
  // about a span ended at response headers: worse than no metric, because it
  // looks like data.
  //
  // Read before `PgUsageStore.record` coerces the column with `?? 0`.
  if (call.durationMs !== undefined) {
    gatewayDuration.record(call.durationMs, {
      // No `appId`: per decision 8's table, the counter carries the per-app
      // breakdown and the histogram does not — a bucket set per app multiplies
      // the series count by the tenant's app count for a question nobody asks.
      [ATTR_CAPABILITY]: call.capability,
      [ATTR_OUTCOME]: call.outcome,
    });
  }
}

export function meterCutCharge(call: { appId: string; basis: CutChargeBasis }): void {
  instruments().gatewayCutCharges.add(1, {
    [ATTR_APP_ID]: call.appId,
    [ATTR_USAGE_BASIS]: call.basis,
  });
}
