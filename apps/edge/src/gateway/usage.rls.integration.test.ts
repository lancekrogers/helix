import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import { PLATFORM_LLM_SPEND_DEFINER_CATALOG_SQL } from "./platformSpendDefinerCheck.js";
import { PgUsageStore } from "./usage.js";
import { TEST_DATABASE_URL } from "../test/seed.js";

const PLATFORM_SPEND_MIGRATION_SQL = readFileSync(
  join(
    dirname(fileURLToPath(import.meta.url)),
    "../../../portal/prisma/migrations/20261009223800_platform_llm_spend_definer/migration.sql",
  ),
  "utf8",
);

/**
 * The gateway ledger against real Postgres, connecting as the least-privilege
 * `helix_edge` role — so this exercises the actual `gateway_calls_edge_partition`
 * RLS policy (ADR-0002 ISSUE-12), not just the hand-written `WHERE "appId"`.
 * The plain `usage.integration.test.ts` runs as the superuser owner (bypasses
 * RLS) and covers the store's column/round-trip logic; this file is the
 * isolation half. Skips when the runtime role isn't provisioned (CI without
 * db-init), same as the other role-split suites.
 */

function edgeUrl(): string {
  const u = new URL(TEST_DATABASE_URL);
  u.username = "helix_edge";
  u.password = "helix_edge";
  return u.toString();
}

async function edgeRoleAvailable(): Promise<boolean> {
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

const APP = randomUUID();
const OTHER_APP = randomUUID();
let store: PgUsageStore | null = null;

afterAll(async () => {
  await store?.close();
  // Clean as the superuser owner — FORCE RLS would otherwise scope a bare delete.
  const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
  try {
    await owner.query(`DELETE FROM gateway_calls WHERE "appId" = ANY($1::uuid[])`, [
      [APP, OTHER_APP],
    ]);
  } finally {
    await owner.end();
  }
});

describe("PgUsageStore as helix_edge (RLS-backed)", () => {
  it("records and sums within the app's partition, isolated from other apps", async () => {
    if (!(await edgeRoleAvailable())) return;
    store = new PgUsageStore(edgeUrl(), { max: 2 });

    // The INSERT lands only because withPartition sets app.app_id to the row's
    // own appId (the WITH CHECK) — a mismatch would be rejected (see below).
    await store.record({
      appId: APP,
      env: "prod",
      userOid: "oid-alice",
      userName: null,
      userEmail: null,
      userKind: "user" as const,
      capability: "llm",
      model: "claude-opus-4-8",
      inputTokens: 100,
      outputTokens: 50,
      costMicroUsd: 150_000,
      outcome: "ok",
    });
    // A different app's usage is written under its own partition…
    await store.record({
      appId: OTHER_APP,
      env: "prod",
      userOid: "oid-bob",
      userName: null,
      userEmail: null,
      userKind: "user" as const,
      capability: "llm",
      model: "claude-opus-4-8",
      inputTokens: 999,
      outputTokens: 999,
      costMicroUsd: 9_999_999,
      outcome: "ok",
    });

    // …and the budget SUM for APP sees only APP's rows, never OTHER_APP's —
    // enforced by RLS, not just the WHERE clause.
    expect(await store.llmSpendMicroUsd(APP, "prod")).toEqual({
      todayMicro: 150_000,
      hourMicro: 150_000,
    });
  });

  it("fails closed: a bare read with no partition GUC sees nothing", async () => {
    if (!(await edgeRoleAvailable())) return;
    // Seed a row so a leak would be observable.
    const s = store ?? new PgUsageStore(edgeUrl(), { max: 1 });
    store = s;
    await s.record({
      appId: APP,
      env: "prod",
      userOid: "oid-alice",
      userName: null,
      userEmail: null,
      userKind: "user" as const,
      capability: "data",
      model: "user.put",
      inputTokens: 0,
      outputTokens: 0,
      outcome: "ok",
    });

    const pool = new Pool({ connectionString: edgeUrl(), max: 1 });
    try {
      // No set_config — the policy predicate is NULL → matches zero rows.
      const r = await pool.query(`SELECT count(*)::int AS n FROM gateway_calls`);
      expect((r.rows[0] as { n: number }).n).toBe(0);
    } finally {
      await pool.end();
    }
  });

  it("rejects a metering INSERT that targets another app's partition (WITH CHECK)", async () => {
    if (!(await edgeRoleAvailable())) return;
    const pool = new Pool({ connectionString: edgeUrl(), max: 1 });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // GUC says APP, but the row says OTHER_APP — the WITH CHECK must reject it,
      // so a confused appId can't forge another app's metering.
      await client.query("SELECT set_config('app.app_id', $1, true)", [APP]);
      await expect(
        client.query(
          `INSERT INTO gateway_calls (id, "appId", "userOid", capability, model, outcome)
             VALUES (gen_random_uuid(), $1, 'x', 'llm', 'm', 'ok')`,
          [OTHER_APP],
        ),
      ).rejects.toThrow(/row-level security/i);
      await client.query("ROLLBACK");
    } finally {
      client.release();
      await pool.end();
    }
  });

  it("helix_edge cannot UPDATE or DELETE gateway_calls rows", async () => {
    if (!(await edgeRoleAvailable())) return;
    const pool = new Pool({ connectionString: edgeUrl(), max: 1 });
    try {
      for (const sql of [
        `UPDATE gateway_calls SET outcome = 'error'`,
        `DELETE FROM gateway_calls`,
      ]) {
        await expect(pool.query(sql)).rejects.toThrow(/permission denied/i);
      }
    } finally {
      await pool.end();
    }
  });
});

async function seedGatewayCost(
  owner: Pool,
  appId: string,
  env: string,
  costMicroUsd: number,
  capability: string,
): Promise<void> {
  await owner.query(
    `INSERT INTO gateway_calls (id, "appId", env, "userOid", capability, model, outcome, "costMicroUsd")
     VALUES (gen_random_uuid(), $1, $2, 'seed', $3, 'm', 'ok', $4)`,
    [appId, env, capability, costMicroUsd],
  );
}

describe("platform_llm_spend_micro_usd (SECURITY DEFINER aggregate)", () => {
  const APP_A = randomUUID();
  const APP_B = randomUUID();
  let owner: Pool | null = null;

  beforeAll(() => {
    owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 2 });
  });

  afterAll(async () => {
    if (owner) {
      await owner.query(`DELETE FROM gateway_calls WHERE "appId" = ANY($1::uuid[])`, [
        [APP_A, APP_B],
      ]);
      await owner.end();
    }
  });

  it("returns the cross-app LLM sum for prod (delta over concurrent suite noise)", async () => {
    if (!(await edgeRoleAvailable()) || !owner) return;
    const pool = new Pool({ connectionString: edgeUrl(), max: 1 });
    try {
      const before = await pool.query(`SELECT * FROM platform_llm_spend_micro_usd('prod')`);
      const b = before.rows[0] as { today: string; hour: string };
      await seedGatewayCost(owner, APP_A, "prod", 100_000, "llm");
      await seedGatewayCost(owner, APP_B, "prod", 200_000, "llm");
      const after = await pool.query(`SELECT * FROM platform_llm_spend_micro_usd('prod')`);
      const a = after.rows[0] as { today: string; hour: string };
      expect(Number(a.today) - Number(b.today)).toBe(300_000);
      expect(Number(a.hour) - Number(b.hour)).toBe(300_000);
    } finally {
      await pool.end();
    }
  });

  it("exposes only today and hour — no per-app breakdown", async () => {
    if (!(await edgeRoleAvailable())) return;
    const pool = new Pool({ connectionString: edgeUrl(), max: 1 });
    try {
      const r = await pool.query(`SELECT * FROM platform_llm_spend_micro_usd('prod')`);
      const names = r.fields.map((f) => f.name);
      expect(names.sort()).toEqual(["hour", "today"]);
      expect(Object.keys(r.rows[0] as object).sort()).toEqual(["hour", "today"]);
    } finally {
      await pool.end();
    }
  });

  it("counts only llm rows in the requested env", async () => {
    if (!(await edgeRoleAvailable()) || !owner) return;
    const pool = new Pool({ connectionString: edgeUrl(), max: 1 });
    const fetchApp = randomUUID();
    const devApp = randomUUID();
    try {
      const before = await pool.query(`SELECT * FROM platform_llm_spend_micro_usd('prod')`);
      const b = before.rows[0] as { today: string };
      await seedGatewayCost(owner, fetchApp, "prod", 50_000_000, "fetch");
      await seedGatewayCost(owner, devApp, "dev", 50_000_000, "llm");
      const after = await pool.query(`SELECT * FROM platform_llm_spend_micro_usd('prod')`);
      const a = after.rows[0] as { today: string };
      expect(Number(a.today) - Number(b.today)).toBe(0);
    } finally {
      await owner.query(`DELETE FROM gateway_calls WHERE "appId" = ANY($1::uuid[])`, [
        [fetchApp, devApp],
      ]);
      await pool.end();
    }
  });

  it("owner policy and definer function are aligned in the catalog", async () => {
    const pool = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    try {
      const r = await pool.query(PLATFORM_LLM_SPEND_DEFINER_CATALOG_SQL);
      expect(r.rows).toHaveLength(1);
      const row = r.rows[0] as Record<string, boolean | string>;
      expect(row.fn_name_ok).toBe(true);
      expect(row.security_definer).toBe(true);
      expect(row.search_path_pinned).toBe(true);
      expect(row.policy_name_ok).toBe(true);
      expect(row.policy_cmd_ok).toBe(true);
      expect(row.policy_admits_owner).toBe(true);
      expect(typeof row.function_owner).toBe("string");
      expect(row.function_owner).toBeTruthy();
    } finally {
      await pool.end();
    }
  });
});

describe("platform_llm_spend_micro_usd owner policy (non-bypass probe)", () => {
  const PROBE_ROLE = "ownerpolicy_probe_sp8";
  const dbName = `ownerpolicy_probe_${randomUUID().replace(/-/g, "")}`;
  let owner: Pool | null = null;
  let probeCanCreate = false;

  beforeAll(async () => {
    owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 2 });
    try {
      await owner.query(`CREATE DATABASE ${dbName}`);
      probeCanCreate = true;
    } catch {
      probeCanCreate = false;
      return;
    }
    try {
      await owner.query(`CREATE ROLE ${PROBE_ROLE} NOSUPERUSER NOBYPASSRLS LOGIN PASSWORD 'probe'`);
    } catch {
      probeCanCreate = false;
      await owner.query(`DROP DATABASE IF EXISTS ${dbName}`);
      return;
    }
    const scratchAdmin = new Pool({
      connectionString: (() => {
        const u = new URL(TEST_DATABASE_URL);
        u.pathname = `/${dbName}`;
        return u.toString();
      })(),
      max: 1,
    });
    try {
      await scratchAdmin.query(`GRANT CREATE ON SCHEMA public TO ${PROBE_ROLE}`);
    } finally {
      await scratchAdmin.end();
    }
    const probeUrl = new URL(TEST_DATABASE_URL);
    probeUrl.pathname = `/${dbName}`;
    probeUrl.username = PROBE_ROLE;
    probeUrl.password = "probe";
    const probe = new Pool({ connectionString: probeUrl.toString(), max: 1 });
    try {
      await probe.query(`
        CREATE TABLE gateway_calls (
          "appId" uuid,
          env text,
          capability text,
          "costMicroUsd" bigint,
          "createdAt" timestamp(3) DEFAULT now()
        )`);
      await probe.query(`ALTER TABLE gateway_calls ENABLE ROW LEVEL SECURITY`);
      await probe.query(`ALTER TABLE gateway_calls FORCE ROW LEVEL SECURITY`);
      await probe.query(PLATFORM_SPEND_MIGRATION_SQL);
      await owner.query(`GRANT CONNECT ON DATABASE ${dbName} TO helix_edge`);
      await probe.query(`GRANT USAGE ON SCHEMA public TO helix_edge`);
    } finally {
      await probe.end();
    }
  });

  afterAll(async () => {
    if (!owner) return;
    if (probeCanCreate) {
      await owner.query(
        `SELECT pg_terminate_backend(pid)
         FROM pg_stat_activity
         WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [dbName],
      );
      await owner.query(`DROP DATABASE IF EXISTS ${dbName}`);
      await owner.query(`DROP ROLE IF EXISTS ${PROBE_ROLE}`);
    }
    await owner.end();
  });

  it("sees non-zero spend with the owner policy and zero after it is dropped", async () => {
    if (!probeCanCreate || !(await edgeRoleAvailable()) || !owner) {
      return;
    }
    const edgeOnScratch = edgeUrl().replace(/\/[^/]+$/, `/${dbName}`);
    const scratchAdmin = new Pool({
      connectionString: (() => {
        const u = new URL(TEST_DATABASE_URL);
        u.pathname = `/${dbName}`;
        return u.toString();
      })(),
      max: 1,
    });
    try {
      await scratchAdmin.query(
        `INSERT INTO gateway_calls ("appId", env, capability, "costMicroUsd")
         VALUES (gen_random_uuid(), 'prod', 'llm', 42_000)`,
      );
    } finally {
      await scratchAdmin.end();
    }
    const edgePool = new Pool({ connectionString: edgeOnScratch, max: 1 });
    try {
      const withPolicy = await edgePool.query(`SELECT * FROM platform_llm_spend_micro_usd('prod')`);
      expect(Number((withPolicy.rows[0] as { today: string }).today)).toBe(42_000);

      const probeUrl = new URL(TEST_DATABASE_URL);
      probeUrl.pathname = `/${dbName}`;
      probeUrl.username = PROBE_ROLE;
      probeUrl.password = "probe";
      const probe = new Pool({ connectionString: probeUrl.toString(), max: 1 });
      try {
        await probe.query(`DROP POLICY gateway_calls_owner_read ON gateway_calls`);
      } finally {
        await probe.end();
      }

      const withoutPolicy = await edgePool.query(
        `SELECT * FROM platform_llm_spend_micro_usd('prod')`,
      );
      expect(Number((withoutPolicy.rows[0] as { today: string }).today)).toBe(0);
    } finally {
      await edgePool.end();
    }
  });
});

describe("PgUsageStore.platformLlmSpendMicroUsd", () => {
  const PLATFORM_APP = randomUUID();

  afterAll(async () => {
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    try {
      await owner.query(`DELETE FROM gateway_calls WHERE "appId" = $1::uuid`, [PLATFORM_APP]);
    } finally {
      await owner.end();
    }
  });

  it("returns the cross-app sum as helix_edge", async () => {
    if (!(await edgeRoleAvailable())) return;
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    const platformStore = new PgUsageStore(edgeUrl(), { max: 2, platformCacheMs: 0 });
    try {
      const before = await platformStore.platformLlmSpendMicroUsd("prod");
      await seedGatewayCost(owner, PLATFORM_APP, "prod", 77_000, "llm");
      const after = await platformStore.platformLlmSpendMicroUsd("prod");
      expect(after.todayMicro - before.todayMicro).toBe(77_000);
    } finally {
      await owner.end();
      await platformStore.close();
    }
  });

  it("includes error rows with positive costMicroUsd", async () => {
    if (!(await edgeRoleAvailable())) return;
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    const platformStore = new PgUsageStore(edgeUrl(), { max: 2, platformCacheMs: 0 });
    try {
      const before = await platformStore.platformLlmSpendMicroUsd("prod");
      await owner.query(
        `INSERT INTO gateway_calls (id, "appId", env, "userOid", capability, model, outcome, "costMicroUsd")
         VALUES (gen_random_uuid(), $1, 'prod', 'seed', 'llm', 'm', 'error', 42_000)`,
        [PLATFORM_APP],
      );
      const after = await platformStore.platformLlmSpendMicroUsd("prod");
      expect(after.todayMicro - before.todayMicro).toBe(42_000);
    } finally {
      await owner.end();
      await platformStore.close();
    }
  });

  it("serves a cached value inside the TTL", async () => {
    if (!(await edgeRoleAvailable())) return;
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    const platformStore = new PgUsageStore(edgeUrl(), { max: 2, platformCacheMs: 60_000 });
    try {
      const first = await platformStore.platformLlmSpendMicroUsd("prod");
      await seedGatewayCost(owner, PLATFORM_APP, "prod", 1, "llm");
      const second = await platformStore.platformLlmSpendMicroUsd("prod");
      expect(second).toEqual(first);
    } finally {
      await owner.end();
      await platformStore.close();
    }
  });

  it("re-reads when caching is disabled", async () => {
    if (!(await edgeRoleAvailable())) return;
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    const platformStore = new PgUsageStore(edgeUrl(), { max: 2, platformCacheMs: 0 });
    try {
      const before = await platformStore.platformLlmSpendMicroUsd("prod");
      await seedGatewayCost(owner, PLATFORM_APP, "prod", 5, "llm");
      const after = await platformStore.platformLlmSpendMicroUsd("prod");
      expect(after.todayMicro).toBe(before.todayMicro + 5);
    } finally {
      await owner.end();
      await platformStore.close();
    }
  });

  it("single-flights concurrent reads", async () => {
    if (!(await edgeRoleAvailable())) return;
    const platformStore = new PgUsageStore(edgeUrl(), { max: 2, platformCacheMs: 0 });
    try {
      const [a, b] = await Promise.all([
        platformStore.platformLlmSpendMicroUsd("prod"),
        platformStore.platformLlmSpendMicroUsd("prod"),
      ]);
      expect(a).toEqual(b);
    } finally {
      await platformStore.close();
    }
  });

  it("checkPlatformSpendFunction returns ok on a migrated database", async () => {
    if (!(await edgeRoleAvailable())) return;
    const platformStore = new PgUsageStore(edgeUrl(), { max: 1 });
    try {
      expect(await platformStore.checkPlatformSpendFunction()).toEqual({ status: "ok" });
    } finally {
      await platformStore.close();
    }
  });
});
