import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import { createEdgePool, withPooledClient, type EdgePoolOpts } from "../db/pool.js";

export interface LeaseRequest {
  /** `llm:app:<appId>`, `llm:user:<appId>:<userOid>`, `fetch:app:<appId>`. */
  scope: string;
  /** Maximum unexpired leases on this scope. 0 or less means no cap: the scope takes no row. */
  cap: number;
}

export type AcquireResult = { ok: true; leaseId: string } | { ok: false; scope: string };

export interface LeaseStore {
  /** All scopes or none. `ttlMs` bounds how long a leaked lease can hold a slot. */
  acquire(requests: readonly LeaseRequest[], ttlMs: number): Promise<AcquireResult>;
  release(leaseId: string): Promise<void>;
  /** GC expired rows. Correctness never depends on it: expired leases are not counted. */
  sweep(): Promise<void>;
  close(): Promise<void>;
}

function cappedRequests(requests: readonly LeaseRequest[]): LeaseRequest[] {
  const byScope = new Map<string, number>();
  for (const { scope, cap } of requests) {
    if (cap <= 0) continue;
    const prev = byScope.get(scope);
    if (prev === undefined || cap < prev) byScope.set(scope, cap);
  }
  return [...byScope.entries()]
    .map(([scope, cap]) => ({ scope, cap }))
    .sort((a, b) => (a.scope < b.scope ? -1 : a.scope > b.scope ? 1 : 0));
}

/**
 * Postgres-backed lease store under the `helix_edge` role (SELECT+INSERT+DELETE on
 * `inflight_leases`). `acquire` takes advisory xact locks per scope (sorted) so
 * check-then-insert is atomic under READ COMMITTED.
 *
 * Lock keys are hashes of the scope string, so two unrelated scopes can collide and
 * serialize needlessly — a little extra latency, never incorrect. Counts use
 * `"expiresAt" > now()` against `timestamp(3)`, the same pattern as {@link PgCounterStore}.
 */
export class PgLeaseStore implements LeaseStore {
  readonly #pool: Pool;

  constructor(databaseUrl: string, opts: EdgePoolOpts = {}) {
    this.#pool = createEdgePool(databaseUrl, {
      ...opts,
      max: opts.max ?? 10,
      connectionTimeoutMs: opts.connectionTimeoutMs ?? 5_000,
      label: opts.label ?? "leases",
    });
  }

  async acquire(requests: readonly LeaseRequest[], ttlMs: number): Promise<AcquireResult> {
    const sorted = cappedRequests(requests);
    const leaseId = randomUUID();
    if (sorted.length === 0) {
      return { ok: true, leaseId };
    }

    return withPooledClient(this.#pool, async (client) => {
      await client.query("BEGIN");
      try {
        for (const { scope } of sorted) {
          await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [scope]);
        }
        for (const { scope, cap } of sorted) {
          const res = await client.query<{ n: number }>(
            `SELECT count(*)::int AS n FROM inflight_leases WHERE scope = $1 AND "expiresAt" > now()`,
            [scope],
          );
          if ((res.rows[0]?.n ?? 0) >= cap) {
            await client.query("ROLLBACK");
            return { ok: false as const, scope };
          }
        }
        await client.query(
          `INSERT INTO inflight_leases (id, scope, "expiresAt")
             SELECT $1::uuid, s, now() + ($3::text || ' milliseconds')::interval
             FROM unnest($2::text[]) AS s`,
          [leaseId, sorted.map((r) => r.scope), ttlMs],
        );
        await client.query("COMMIT");
        return { ok: true as const, leaseId };
      } catch (err) {
        await client.query("ROLLBACK").catch(() => {});
        throw err;
      }
    });
  }

  async release(leaseId: string): Promise<void> {
    await this.#pool.query(`DELETE FROM inflight_leases WHERE id = $1`, [leaseId]);
  }

  async sweep(): Promise<void> {
    await this.#pool.query(`DELETE FROM inflight_leases WHERE "expiresAt" < now()`);
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }
}

/**
 * In-memory lease store for unit tests and single-process dev. NOT multi-replica safe.
 */
export class InMemoryLeaseStore implements LeaseStore {
  /** scope → leaseId → expiresAt (epoch ms) */
  readonly #leases = new Map<string, Map<string, number>>();
  readonly #now: () => number;

  constructor(now: () => number = Date.now) {
    this.#now = now;
  }

  async acquire(requests: readonly LeaseRequest[], ttlMs: number): Promise<AcquireResult> {
    const sorted = cappedRequests(requests);
    const leaseId = randomUUID();
    if (sorted.length === 0) {
      return { ok: true, leaseId };
    }

    const t = this.#now();
    for (const { scope, cap } of sorted) {
      const active = this.#countActive(scope, t);
      if (active >= cap) {
        return { ok: false, scope };
      }
    }
    const expiresAt = t + ttlMs;
    for (const { scope } of sorted) {
      let m = this.#leases.get(scope);
      if (!m) {
        m = new Map();
        this.#leases.set(scope, m);
      }
      m.set(leaseId, expiresAt);
    }
    return { ok: true, leaseId };
  }

  async release(leaseId: string): Promise<void> {
    for (const m of this.#leases.values()) {
      m.delete(leaseId);
    }
  }

  async sweep(): Promise<void> {
    const t = this.#now();
    for (const [scope, m] of this.#leases) {
      for (const [id, exp] of m) {
        if (exp <= t) m.delete(id);
      }
      if (m.size === 0) this.#leases.delete(scope);
    }
  }

  async close(): Promise<void> {}

  /** Unexpired leases on `scope` — for tests only. */
  held(scope: string): number {
    return this.#countActive(scope, this.#now());
  }

  #countActive(scope: string, t: number): number {
    const m = this.#leases.get(scope);
    if (!m) return 0;
    let n = 0;
    for (const exp of m.values()) {
      if (exp > t) n += 1;
    }
    return n;
  }
}
