import { randomUUID } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TEST_DATABASE_URL } from "../test/seed.js";
import { PgLeaseStore } from "./leaseStore.js";

function edgeUrl(): string {
  const u = new URL(TEST_DATABASE_URL);
  u.username = "helix_edge";
  u.password = "helix_edge";
  return u.toString();
}

async function available(): Promise<boolean> {
  const pool = new Pool({ connectionString: edgeUrl(), max: 1 });
  try {
    await pool.query("SELECT 1");
    return true;
  } catch {
    return false;
  } finally {
    await pool.end();
  }
}

let ok = false;
let store: PgLeaseStore;
const scopes: string[] = [];
function scope(): string {
  const s = `test:${randomUUID()}`;
  scopes.push(s);
  return s;
}

beforeAll(async () => {
  ok = await available();
  if (ok) store = new PgLeaseStore(edgeUrl());
});

afterAll(async () => {
  if (scopes.length) {
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    await owner.query(`DELETE FROM inflight_leases WHERE scope LIKE 'test:%'`);
    await owner.end();
  }
  await store?.close();
});

describe("PgLeaseStore (helix_edge)", () => {
  it("acquires, refuses at cap, and release frees a slot", async () => {
    if (!ok) return;
    const s = scope();
    const cap = 2;
    const a = await store.acquire([{ scope: s, cap }], 60_000);
    const b = await store.acquire([{ scope: s, cap }], 60_000);
    expect(a.ok && b.ok).toBe(true);
    expect(await store.acquire([{ scope: s, cap }], 60_000)).toEqual({ ok: false, scope: s });
    if (a.ok) await store.release(a.leaseId);
    expect(await store.acquire([{ scope: s, cap }], 60_000)).toEqual({
      ok: true,
      leaseId: expect.any(String),
    });
  });

  it("exactly cap successes under 50 parallel acquires (cap 5)", async () => {
    if (!ok) return;
    const s = scope();
    const cap = 5;
    const results = await Promise.all(
      Array.from({ length: 50 }, () => store.acquire([{ scope: s, cap }], 60_000)),
    );
    const wins = results.filter((r) => r.ok);
    expect(wins).toHaveLength(cap);
  });

  it("two replicas on separate pools: cap 5 total across 50 parallel acquires", async () => {
    if (!ok) return;
    const s = scope();
    const cap = 5;
    const a = new PgLeaseStore(edgeUrl(), { label: "leases-a", max: 15 });
    const b = new PgLeaseStore(edgeUrl(), { label: "leases-b", max: 15 });
    try {
      const results = await Promise.all([
        ...Array.from({ length: 25 }, () => a.acquire([{ scope: s, cap }], 60_000)),
        ...Array.from({ length: 25 }, () => b.acquire([{ scope: s, cap }], 60_000)),
      ]);
      expect(results.filter((r) => r.ok)).toHaveLength(cap);
    } finally {
      await a.close();
      await b.close();
    }
  });

  it("no deadlock when scopes are ordered [A,B] vs [B,A]", async () => {
    if (!ok) return;
    const prefix = scope();
    const A = `${prefix}:A`;
    const B = `${prefix}:B`;
    const cap = 100;
    const errors: unknown[] = [];
    const run = async (reqs: { scope: string; cap: number }[]) => {
      try {
        return await store.acquire(reqs, 60_000);
      } catch (err) {
        errors.push(err);
        throw err;
      }
    };
    const results = await Promise.all([
      ...Array.from({ length: 40 }, () =>
        run([
          { scope: A, cap },
          { scope: B, cap },
        ]),
      ),
      ...Array.from({ length: 40 }, () =>
        run([
          { scope: B, cap },
          { scope: A, cap },
        ]),
      ),
    ]);
    for (const err of errors) {
      const code = (err as { code?: string }).code;
      expect(code).not.toBe("40P01");
    }
    expect(results.every((r) => r.ok)).toBe(true);
  });

  it("expired lease does not count without sweep (negative TTL)", async () => {
    if (!ok) return;
    const s = scope();
    expect(await store.acquire([{ scope: s, cap: 1 }], -1000)).toEqual({
      ok: true,
      leaseId: expect.any(String),
    });
    expect(await store.acquire([{ scope: s, cap: 1 }], 60_000)).toEqual({
      ok: true,
      leaseId: expect.any(String),
    });
  });

  it("crash simulation: TTL expiry frees cap-1 scope without release", async () => {
    if (!ok) return;
    const s = scope();
    expect(await store.acquire([{ scope: s, cap: 1 }], 200)).toEqual({
      ok: true,
      leaseId: expect.any(String),
    });
    expect(await store.acquire([{ scope: s, cap: 1 }], 60_000)).toEqual({ ok: false, scope: s });
    await sleep(250);
    expect(await store.acquire([{ scope: s, cap: 1 }], 60_000)).toEqual({
      ok: true,
      leaseId: expect.any(String),
    });
  });

  it("sweep() removes expired rows", async () => {
    if (!ok) return;
    const s = scope();
    await store.acquire([{ scope: s, cap: 5 }], -1000);
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    const before = await owner.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM inflight_leases WHERE scope = $1`,
      [s],
    );
    expect(before.rows[0]?.n).toBeGreaterThan(0);
    await store.sweep();
    const after = await owner.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM inflight_leases WHERE scope = $1`,
      [s],
    );
    await owner.end();
    expect(after.rows[0]?.n).toBe(0);
  });

  it("a refused acquire leaves no row for any of its scopes", async () => {
    if (!ok) return;
    const prefix = scope();
    const full = `${prefix}:full`;
    const open = `${prefix}:open`;
    await store.acquire([{ scope: full, cap: 1 }], 60_000);
    const denied = await store.acquire(
      [
        { scope: open, cap: 10 },
        { scope: full, cap: 1 },
      ],
      60_000,
    );
    expect(denied).toEqual({ ok: false, scope: full });
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    const rows = await owner.query<{ scope: string }>(
      `SELECT scope FROM inflight_leases WHERE scope LIKE $1`,
      [`${prefix}%`],
    );
    await owner.end();
    expect(rows.rows.map((r) => r.scope).sort()).toEqual([full]);
  });
});
