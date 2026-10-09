import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";
import { PROVIDERS_CHANNEL } from "@azx-pbc/shared";
import { TEST_DATABASE_URL } from "../test/seed.js";

/**
 * App-data design §2.1 — the database-role split, asserted against the real
 * cluster. The edge runtime role (`helix_edge`) holds a tight union of the
 * data-plane verbs and nothing more: it reads the registry but cannot write it,
 * and it is not the table owner (no DDL). The containment that survives an edge
 * RCE is exactly the GRANTs that are absent. The companion §3.2 assertion —
 * `helix_edge` cannot SELECT collection items — lands with that table (Phase 5).
 *
 * The runtime roles are created by db-init/01-roles.sql (or Terraform), not by
 * migrations, so on a cluster without them this whole suite skips rather than
 * failing — same fail-soft stance as the guarded grants migration.
 */

/** The edge role's URL, derived from the owner test URL by swapping creds. */
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

describe("helix_edge least-privilege grants", () => {
  it("reads the registry but cannot write it, and cannot drop tables", async () => {
    if (!(await edgeRoleAvailable())) {
      // Roles not provisioned on this cluster (e.g. CI without db-init) — the
      // grants migration was a no-op too, so there is nothing to assert.
      return;
    }
    const pool = new Pool({ connectionString: edgeUrl(), max: 1 });
    try {
      // Read-only registry projection: SELECT is granted.
      await expect(pool.query("SELECT count(*) FROM apps")).resolves.toBeDefined();
      await expect(pool.query("SELECT count(*) FROM versions")).resolves.toBeDefined();

      // The meter: SELECT + INSERT on gateway_calls. The grant is present, so
      // this resolves; RLS (ADR-0002) makes it count 0 with no partition
      // GUC set — the isolation itself is asserted in usage.rls.integration.test.ts.
      await expect(pool.query("SELECT count(*) FROM gateway_calls")).resolves.toBeDefined();

      // Registry is read-only — no INSERT grant on apps.
      await expect(
        pool.query(
          `INSERT INTO apps (id, slug, "displayName", "visibilityMode")
           VALUES (gen_random_uuid(), 'rolesplit', 'x', 'internal')`,
        ),
      ).rejects.toThrow(/permission denied/i);

      // CSP reports (§6.2): INSERT-only, write-from-edge. Append is granted…
      await expect(
        pool.query(
          `INSERT INTO csp_reports (id, "appId", directive, "blockedUri")
           VALUES (gen_random_uuid(), gen_random_uuid(), 'connect-src', 'https://x')`,
        ),
      ).resolves.toBeDefined();
      // …but the edge can NEVER enumerate them (no SELECT grant).
      await expect(pool.query("SELECT count(*) FROM csp_reports")).rejects.toThrow(
        /permission denied/i,
      );

      // The approvals queue is portal-only — the edge has no grant at all.
      await expect(pool.query("SELECT count(*) FROM approval_requests")).rejects.toThrow(
        /permission denied/i,
      );

      // Connection secrets (secrets design §4): read ONLY by helix_egress. The
      // policy edge has no grant — that absence is the secret-custody boundary,
      // and it is table-wide, so it covers `platform`-scoped rows (the LLM vendor
      // key) too: an edge RCE cannot read the vendor key any more than an app key.
      await expect(pool.query("SELECT count(*) FROM app_secrets")).rejects.toThrow(
        /permission denied/i,
      );
      await expect(
        pool.query("SELECT material FROM app_secrets WHERE scope = 'platform'"),
      ).rejects.toThrow(/permission denied/i);

      // Abuse-control counters (issue #13): the edge OWNS rate_counters — full
      // CRUD for the atomic upsert / clear / sweep.
      await expect(pool.query("SELECT count(*) FROM rate_counters")).resolves.toBeDefined();
      await expect(
        pool.query(
          `INSERT INTO rate_counters ("bucketKey", count, "resetAt") VALUES ('rs-edge', 1, now())`,
        ),
      ).resolves.toBeDefined();
      await expect(
        pool.query(`DELETE FROM rate_counters WHERE "bucketKey" = 'rs-edge'`),
      ).resolves.toBeDefined();
      // …but the egress-owned jti burn set is off-limits (no grant at all).
      await expect(pool.query("SELECT count(*) FROM instruction_jti")).rejects.toThrow(
        /permission denied/i,
      );
      // And so is the control plane's own counter table (ADR-0040 §4). This is
      // the mirror image of the portal being kept out of `rate_counters`, and it
      // is the property that whole second table exists to buy: neither plane can
      // reach into the other's abuse-control state. Asserted from this side too
      // because a blanket `ON ALL TABLES` bootstrap would widen it silently.
      await expect(pool.query("SELECT count(*) FROM portal_rate_counters")).rejects.toThrow(
        /permission denied/i,
      );

      // Not the owner — no DDL.
      await expect(pool.query("DROP TABLE apps")).rejects.toThrow(/must be owner/i);
    } finally {
      await pool.end();
    }
  });

  /**
   * The connection substrate — the strictest role
   * split the platform has: the edge consults the portal over HTTP (ADR-0002),
   * so it gains ZERO database grants on the provider catalog, the per-user
   * connections, or the consent-flow table. Grant-absence is the containment:
   * an edge RCE reaches no provider row, no user's delegated material, no
   * consent-flow state — not even a status it could enumerate.
   */
  it("has no grant at all on connection_providers, user_connections, or the consent-flow table", async () => {
    if (!(await edgeRoleAvailable())) return;
    const pool = new Pool({ connectionString: edgeUrl(), max: 1 });
    try {
      await expect(pool.query("SELECT count(*) FROM connection_providers")).rejects.toThrow(
        /permission denied/i,
      );
      await expect(pool.query("SELECT count(*) FROM user_connections")).rejects.toThrow(
        /permission denied/i,
      );
      await expect(pool.query("SELECT count(*) FROM connection_consent_attempts")).rejects.toThrow(
        /permission denied/i,
      );
      // The write half of the absence: the edge cannot INSERT into the
      // consent-flow table either.
      await expect(
        pool.query(
          `INSERT INTO connection_consent_attempts (id, state, "codeVerifier", "userOid",
             "providerId", "providerRevision", "appId", env, "openerOrigin", "expiresAt")
           VALUES (gen_random_uuid(), 'rs-edge-state', 'verifier', 'rs-edge',
                   gen_random_uuid(), 1, gen_random_uuid(), 'prod', 'https://app.example',
                   now() + interval '5 minutes')`,
        ),
      ).rejects.toThrow(/permission denied/i);
    } finally {
      await pool.end();
    }
  });
});

/** The egress role's URL, derived from the owner test URL by swapping creds. */
function egressUrl(): string {
  const u = new URL(TEST_DATABASE_URL);
  u.username = "helix_egress";
  u.password = "helix_egress";
  return u.toString();
}

async function egressRoleAvailable(): Promise<boolean> {
  const pool = new Pool({ connectionString: egressUrl(), max: 1 });
  try {
    await pool.query("SELECT 1");
    return true;
  } catch {
    return false;
  } finally {
    await pool.end();
  }
}

describe("helix_egress least-privilege grants", () => {
  it("resolves secrets but cannot read the registry, sessions, or the ledger", async () => {
    if (!(await egressRoleAvailable())) return; // not provisioned on this cluster

    const pool = new Pool({ connectionString: egressUrl(), max: 1 });
    try {
      // The mechanism plane's job: read connection secrets + their grants.
      await expect(pool.query("SELECT count(*) FROM app_secrets")).resolves.toBeDefined();
      await expect(pool.query("SELECT count(*) FROM app_secret_grants")).resolves.toBeDefined();
      // …and stamp last-used (the only column it may write).
      await expect(
        pool.query(
          `UPDATE app_secrets SET "lastUsedAt" = now()
           WHERE id = '00000000-0000-0000-0000-000000000000'`,
        ),
      ).resolves.toBeDefined();

      // It must NOT be able to alter the credential material…
      await expect(
        pool.query(
          `UPDATE app_secrets SET material = 'x'
           WHERE id = '00000000-0000-0000-0000-000000000000'`,
        ),
      ).rejects.toThrow(/permission denied/i);

      // …nor touch anything the policy plane owns: registry, sessions, ledger.
      await expect(pool.query("SELECT count(*) FROM apps")).rejects.toThrow(/permission denied/i);
      await expect(pool.query("SELECT count(*) FROM sessions")).rejects.toThrow(
        /permission denied/i,
      );
      await expect(pool.query("SELECT count(*) FROM gateway_calls")).rejects.toThrow(
        /permission denied/i,
      );

      // The replay burn (issue #3): egress fully manages instruction_jti —
      // SELECT+INSERT+DELETE (its first write grants), enough for the ON CONFLICT
      // burn and the WHERE-filtered sweep.
      await expect(pool.query("SELECT count(*) FROM instruction_jti")).resolves.toBeDefined();
      await expect(
        pool.query(
          `INSERT INTO instruction_jti (jti, "expiresAt")
           VALUES ('rs-egress', now() + interval '1 minute') ON CONFLICT (jti) DO NOTHING`,
        ),
      ).resolves.toBeDefined();
      await expect(
        pool.query(`DELETE FROM instruction_jti WHERE jti = 'rs-egress'`),
      ).resolves.toBeDefined();
      // …but no grant at all on the edge's abuse-control counters.
      await expect(pool.query("SELECT count(*) FROM rate_counters")).rejects.toThrow(
        /permission denied/i,
      );

      // Not the owner — no DDL.
      await expect(pool.query("DROP TABLE app_secrets")).rejects.toThrow(/must be owner/i);
    } finally {
      await pool.end();
    }
  });
});

/** The dev data-plane role's URL, derived from the owner test URL by swapping creds. */
function devUrl(): string {
  const u = new URL(TEST_DATABASE_URL);
  u.username = "helix_dev";
  u.password = "helix_dev";
  return u.toString();
}

function portalUrl(): string {
  const u = new URL(TEST_DATABASE_URL);
  u.username = "helix_portal";
  u.password = "helix_portal";
  return u.toString();
}

async function portalRoleAvailable(): Promise<boolean> {
  const pool = new Pool({ connectionString: portalUrl(), max: 1 });
  try {
    await pool.query("SELECT 1");
    return true;
  } catch {
    return false;
  } finally {
    await pool.end();
  }
}

async function devRoleAvailable(): Promise<boolean> {
  const pool = new Pool({ connectionString: devUrl(), max: 1 });
  try {
    await pool.query("SELECT 1");
    return true;
  } catch {
    return false;
  } finally {
    await pool.end();
  }
}

/**
 * The admin session-revoke grant set (portal Sessions screen, migration
 * 20260921120000). The control plane may READ live sessions (the admin list)
 * and DELETE them (the user-level kill) — and nothing else, because both of
 * the revoked verbs are *credential* powers: INSERT mints a session for any
 * app and user, and UPDATE is how a session is stolen (rebind `tokenHash` to
 * an attacker's cookie hash) or resurrected (wind `expiresAt` back). The
 * handoff's single-use redeem must stay edge-only by grant, not convention.
 */
describe("helix_portal on sessions: the admin revoke grant set", () => {
  it("reads and deletes sessions but cannot mint or rebind one", async () => {
    if (!(await portalRoleAvailable())) return; // not provisioned on this cluster
    const pool = new Pool({ connectionString: portalUrl(), max: 1 });
    try {
      // The Sessions screen's two verbs.
      await expect(pool.query("SELECT count(*) FROM sessions")).resolves.toBeDefined();
      // A DELETE that matches nothing still exercises the grant, without
      // destroying rows this shared database's other tests own.
      await expect(
        pool.query(`DELETE FROM sessions WHERE "userOid" = 'rs-portal-none'`),
      ).resolves.toBeDefined();

      // The revoked powers. Permission is refused ahead of any constraint or
      // RLS check, so the FK and the no-op WHERE never matter.
      await expect(
        pool.query(
          `INSERT INTO sessions (id, "appId", "userOid", "displayName", groups, "refreshDueAt", "expiresAt")
             VALUES (gen_random_uuid(), gen_random_uuid(), 'x', 'X', '[]'::jsonb,
                     now() + interval '1 hour', now() + interval '1 hour')`,
        ),
      ).rejects.toThrow(/permission denied/i);
      await expect(
        pool.query(
          `UPDATE sessions SET "tokenHash" = 'x' WHERE id = '00000000-0000-0000-0000-000000000000'`,
        ),
      ).rejects.toThrow(/permission denied/i);
    } finally {
      await pool.end();
    }
  });
});

/**
 * Dev-mode design §5.3 — the load-bearing security thesis: the database itself
 * refuses to cross the env boundary. `helix_edge`'s RLS policy hardcodes
 * env='prod' and `helix_dev`'s hardcodes env='dev', so neither can read or write
 * the other tier's rows — independent of the `app.env` GUC, any header, or a
 * WHERE clause. The two isolation reads below (dev can't see a prod row; edge
 * can't see a dev row) and the forged-GUC read are the whole feature's proof that
 * dev mode is not a relaxation of the production APIs but a separate partition.
 *
 * That neither role is BYPASSRLS is proven implicitly: a BYPASSRLS role would see
 * BOTH seeded rows in the reads below. Skips fail-soft when helix_dev isn't
 * provisioned (CI without db-init), same as the suites above.
 */
describe("env partition isolation: helix_dev vs helix_edge (dev-mode §5.3)", () => {
  const APP = randomUUID();
  const USER = "env-user";

  beforeAll(async () => {
    if (!(await devRoleAvailable())) return;
    // Seed one prod row and one dev row for the same (app, user, key) as the
    // superuser owner (bypasses RLS). Distinct values so a leak is observable.
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    try {
      await owner.query(
        `INSERT INTO app_data (id, "appId", env, "userOid", key, value, "updatedAt") VALUES
           (gen_random_uuid(), $1, 'prod', $2, 'k', '"PROD"'::jsonb, now()),
           (gen_random_uuid(), $1, 'dev',  $2, 'k', '"DEV"'::jsonb,  now())`,
        [APP, USER],
      );
    } finally {
      await owner.end();
    }
  });

  afterAll(async () => {
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    try {
      await owner.query(`DELETE FROM app_data WHERE "appId" = $1`, [APP]);
    } finally {
      await owner.end();
    }
  });

  /** Read the seeded key as `url`'s role, with the partition GUCs set (env = `gucEnv`). */
  async function readAs(url: string, gucEnv: "prod" | "dev"): Promise<unknown[]> {
    const pool = new Pool({ connectionString: url, max: 1 });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        "SELECT set_config('app.app_id', $1, true), set_config('app.env', $2, true), set_config('app.user_oid', $3, true)",
        [APP, gucEnv, USER],
      );
      const r = await client.query(`SELECT value FROM app_data WHERE key = 'k'`);
      await client.query("ROLLBACK");
      return (r.rows as { value: unknown }[]).map((row) => row.value);
    } finally {
      client.release();
      await pool.end();
    }
  }

  /** Attempt to INSERT an `rowEnv`-tier row as `url`'s role; the WITH CHECK governs. */
  async function writeAs(url: string, rowEnv: "prod" | "dev"): Promise<void> {
    const pool = new Pool({ connectionString: url, max: 1 });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        "SELECT set_config('app.app_id', $1, true), set_config('app.env', $2, true), set_config('app.user_oid', $3, true)",
        [APP, rowEnv, USER],
      );
      try {
        await client.query(
          `INSERT INTO app_data (id, "appId", env, "userOid", key, value, "updatedAt")
             VALUES (gen_random_uuid(), $1, $2, $3, 'w', '"x"'::jsonb, now())`,
          [APP, rowEnv, USER],
        );
      } finally {
        await client.query("ROLLBACK");
      }
    } finally {
      client.release();
      await pool.end();
    }
  }

  it("helix_dev reads ONLY the dev row (its policy hardcodes env='dev')", async () => {
    if (!(await devRoleAvailable())) return;
    expect(await readAs(devUrl(), "dev")).toEqual(["DEV"]);
  });

  it("helix_edge reads ONLY the prod row (its policy hardcodes env='prod')", async () => {
    if (!(await devRoleAvailable())) return;
    expect(await readAs(edgeUrl(), "prod")).toEqual(["PROD"]);
  });

  it("a forged app.env GUC cannot cross the boundary — the role literal wins", async () => {
    if (!(await devRoleAvailable())) return;
    // helix_dev forging env=prod still sees only its dev row…
    expect(await readAs(devUrl(), "prod")).toEqual(["DEV"]);
    // …and helix_edge forging env=dev still sees only its prod row.
    expect(await readAs(edgeUrl(), "dev")).toEqual(["PROD"]);
  });

  it("write containment: each role's WITH CHECK refuses the other tier's env", async () => {
    if (!(await devRoleAvailable())) return;
    // helix_dev cannot write a prod row…
    await expect(writeAs(devUrl(), "prod")).rejects.toThrow(/row-level security/i);
    // …and helix_edge cannot write a dev row.
    await expect(writeAs(edgeUrl(), "dev")).rejects.toThrow(/row-level security/i);
  });

  /**
   * The portal half of ADR-0040 §4's separation. `rate_counters` is shared with
   * the edge, which keys its shared-password login throttle and anonymous IP
   * limiter there — so portal write access to it would mean the control plane
   * (or a portal RCE) could zero the edge's brute-force protection, and Postgres
   * cannot scope that grant by key prefix. Hence a second table. Both halves are
   * asserted: a migration that "helpfully" re-granted the shared table would
   * otherwise pass every test in the suite.
   */
  it("helix_portal owns its own counters and still cannot touch the edge's", async () => {
    if (!(await portalRoleAvailable())) return;
    const pool = new Pool({ connectionString: portalUrl(), max: 1 });
    try {
      await expect(
        pool.query(
          `INSERT INTO portal_rate_counters ("bucketKey", count, "resetAt")
             VALUES ('rs-portal', 1, now())
           ON CONFLICT ("bucketKey") DO UPDATE SET count = portal_rate_counters.count + 1`,
        ),
      ).resolves.toBeDefined();
      await expect(
        pool.query(`DELETE FROM portal_rate_counters WHERE "bucketKey" = 'rs-portal'`),
      ).resolves.toBeDefined();

      // The edge's table: readable (it holds no secret), but not writable.
      for (const sql of [
        `INSERT INTO rate_counters ("bucketKey", count, "resetAt") VALUES ('rs-x', 1, now())`,
        `UPDATE rate_counters SET count = 0`,
        `DELETE FROM rate_counters`,
      ]) {
        await expect(pool.query(sql)).rejects.toThrow(/permission denied/i);
      }
    } finally {
      await pool.end();
    }
  });

  it("helix_dev holds the least-privilege data-plane grant set and nothing more", async () => {
    if (!(await devRoleAvailable())) return;
    const pool = new Pool({ connectionString: devUrl(), max: 1 });
    try {
      // Owns its data-plane verbs — the grant is present; RLS scopes the rows.
      await expect(pool.query("SELECT count(*) FROM app_data")).resolves.toBeDefined();
      await expect(pool.query("SELECT count(*) FROM gateway_calls")).resolves.toBeDefined();
      // Collections are write-only in dev too (§3.2): INSERT grant, no SELECT.
      await expect(pool.query("SELECT count(*) FROM app_collection_items")).rejects.toThrow(
        /permission denied/i,
      );
      // Reads the registry projection to route (dev-mode §5.4, dev_registry_grant
      // _columns) — but ONLY the non-secret columns, under a column-scoped grant.
      //
      // `visibilityGroupIds` is named explicitly, and that is the point rather
      // than thoroughness. A column-scoped grant enumerates columns, so ANY
      // migration that renames or replaces one silently drops it from the grant
      // and the failure is a runtime `permission denied` in the dev-gateway on a
      // query that type-checks and passes every unit test. ADR-0040 renamed this
      // exact column, and before this line the suite asserted only
      // `visibilityMode` — so it would have gone green through the breakage.
      // Whatever the registry projection selects, assert here.
      await expect(
        pool.query(
          `SELECT slug, "visibilityMode", "visibilityGroupIds", capabilities FROM apps LIMIT 1`,
        ),
      ).resolves.toBeDefined();
      await expect(pool.query("SELECT count(*) FROM versions")).resolves.toBeDefined();
      // The prod password columns are OFF-LIMITS — a compromised dev-gateway can't
      // read a `password`-app credential for any prod app (the isolation thesis).
      await expect(pool.query(`SELECT "passwordHash" FROM apps LIMIT 1`)).rejects.toThrow(
        /permission denied/i,
      );
      await expect(pool.query(`SELECT "passwordSalt" FROM apps LIMIT 1`)).rejects.toThrow(
        /permission denied/i,
      );
      await expect(pool.query(`SELECT "passwordEnc" FROM apps LIMIT 1`)).rejects.toThrow(
        /permission denied/i,
      );
      // No registry writes, no secret read, no DDL.
      await expect(
        pool.query(
          `INSERT INTO apps (id, slug, "displayName", "visibilityMode")
           VALUES (gen_random_uuid(), 'devrs', 'x', 'internal')`,
        ),
      ).rejects.toThrow(/permission denied/i);
      await expect(pool.query("SELECT count(*) FROM app_secrets")).rejects.toThrow(
        /permission denied/i,
      );
      await expect(pool.query("DROP TABLE apps")).rejects.toThrow(/must be owner/i);
    } finally {
      await pool.end();
    }
  });
});

/**
 * The connection substrate's grant matrix, asserted
 * against the real cluster with the runtime roles provisioned: egress gets its
 * exact narrow surface, the portal full DML, the edge nothing (asserted above),
 * and env-literal RLS partitions every table from first commit. A green run
 * with the roles unprovisioned is NOT evidence — each block reports visibly via
 * its availability check, and CI provisions the roles from the same db-init
 * SQL (github/workflows/ci.yml) before this suite runs.
 */
describe("connection substrate: grants, RLS, and the NOTIFY channel", () => {
  const PROVIDER_ID = randomUUID();
  const REF = `rs-provider-${randomUUID().replace(/-/g, "").slice(0, 12)}`;
  const USER = `conn-user-${randomUUID().replace(/-/g, "").slice(0, 12)}`;
  const APP_ID = randomUUID();

  beforeAll(async () => {
    if (!(await portalRoleAvailable())) return;
    // Seed as the superuser owner (bypasses RLS): one prod provider, a prod
    // and a dev connection for the same (userOid, providerId) with DISTINCT
    // sealed material so a cross-tier leak is observable, and one pending
    // consent attempt.
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    try {
      await owner.query(
        `INSERT INTO connection_providers (id, ref, kind, "displayName", "authorizeEndpoint",
           "tokenEndpoint", "requestedScopes", "apiOrigins", "tokenPlacement", env,
           "clientIdMaterial", "clientSecretMaterial", revision, "createdAt", "updatedAt")
         VALUES ($1, $2, 'rest-delegated', 'role-split fixture', 'https://vendor.example/authorize',
           'https://vendor.example/token', '[]'::jsonb, '["https://app.example.com"]'::jsonb,
           '{"kind":"header-bearer"}'::jsonb, 'prod', 'sealed-client-id', 'sealed-client-secret',
           1, now(), now())`,
        [PROVIDER_ID, REF],
      );
      await owner.query(
        `INSERT INTO user_connections (id, "userOid", "providerId", "providerRevision", env,
           status, material, "grantedScopes", "grantedAt", "expiresAt", "renewBeforeNext",
           "pendingRetire", "lastRenewedAt", "createdAt", "updatedAt")
         VALUES (gen_random_uuid(), $1, $2, 1, 'prod', 'live', 'PROD-MATERIAL', '[]'::jsonb,
                 now(), now() + interval '1 hour', false, NULL, NULL, now(), now()),
                (gen_random_uuid(), $1, $2, 1, 'dev',  'live', 'DEV-MATERIAL',  '[]'::jsonb,
                 now(), now() + interval '1 hour', false, NULL, NULL, now(), now())`,
        [USER, PROVIDER_ID],
      );
      await owner.query(
        `INSERT INTO connection_consent_attempts (id, state, "codeVerifier", "userOid",
           "providerId", "providerRevision", "appId", env, "openerOrigin", "expiresAt", "createdAt")
         VALUES (gen_random_uuid(), 'rs-attempt-state', 'rs-verifier', $1, $2, 1, $3, 'prod',
                 'https://app.example.com', now() + interval '5 minutes', now())`,
        [USER, PROVIDER_ID, APP_ID],
      );
    } finally {
      await owner.end();
    }
  });

  afterAll(async () => {
    if (!(await portalRoleAvailable())) return;
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    try {
      // No FKs to cascade through (the substrate is deliberately FK-free),
      // so delete each table explicitly.
      await owner.query(`DELETE FROM connection_consent_attempts WHERE "userOid" = $1`, [USER]);
      await owner.query(`DELETE FROM user_connections WHERE "providerId" = $1`, [PROVIDER_ID]);
      await owner.query(`DELETE FROM connection_providers WHERE id = $1`, [PROVIDER_ID]);
    } finally {
      await owner.end();
    }
  });

  it("helix_egress reads the provider catalog and connections but nothing on the flow table", async () => {
    if (!(await egressRoleAvailable())) return;
    const pool = new Pool({ connectionString: egressUrl(), max: 1 });
    try {
      // SELECT on the catalog — egress opens the sealed client credentials to
      // build the vendor OAuth client. The row must come
      // back through FORCE RLS (its permissive pass — no literal can pin a
      // role that legitimately serves both tiers).
      const providers = await pool.query(`SELECT ref FROM connection_providers WHERE id = $1`, [
        PROVIDER_ID,
      ]);
      expect(providers.rows).toEqual([{ ref: REF }]);

      // SELECT on connections — the delegated resolver reads the row by
      // (userOid, providerId, env).
      await expect(pool.query("SELECT count(*) FROM user_connections")).resolves.toBeDefined();

      // NOTHING on the flow table — consent state is control-plane-owned;
      // egress never sees a pending attempt.
      for (const sql of [
        "SELECT count(*) FROM connection_consent_attempts",
        `INSERT INTO connection_consent_attempts (id, state, "codeVerifier", "userOid",
           "providerId", "providerRevision", "appId", env, "openerOrigin", "expiresAt")
         VALUES (gen_random_uuid(), 's', 'v', 'x', gen_random_uuid(), 1, gen_random_uuid(),
                 'prod', 'https://app.example', now() + interval '5 minutes')`,
        `UPDATE connection_consent_attempts SET "codeVerifier" = 'x' WHERE id = gen_random_uuid()`,
        `DELETE FROM connection_consent_attempts WHERE id = gen_random_uuid()`,
      ]) {
        await expect(pool.query(sql)).rejects.toThrow(/permission denied/i);
      }
    } finally {
      await pool.end();
    }
  });

  it("helix_egress UPDATEs user_connections ONLY within the scoped column list", async () => {
    if (!(await egressRoleAvailable())) return;
    const pool = new Pool({ connectionString: egressUrl(), max: 1 });
    try {
      // The renewal writer's whole surface: the
      // material swap, expiry, granted scopes, the status the renewal outcome
      // records, the ledger fields, and the renew-before-next flag
      // — in one UPDATE, the way the renewal actually writes them.
      const connId = (
        await pool.query(
          `SELECT id FROM user_connections WHERE "userOid" = $1 AND "providerId" = $2 AND env = 'prod'`,
          [USER, PROVIDER_ID],
        )
      ).rows[0]!.id;
      await expect(
        pool.query(
          `UPDATE user_connections SET material = 'NEW-MATERIAL', "expiresAt" = now() + interval '2 hours',
             "grantedScopes" = '["projects:read"]'::jsonb, status = 'live', "renewBeforeNext" = false,
             "pendingRetire" = 'PROD-MATERIAL', "lastRenewedAt" = now()
           WHERE id = $1`,
          [connId],
        ),
      ).resolves.toBeDefined();

      // Out of scope — identity, key, provenance, provenance stamps. Permission
      // is refused ahead of any row match, so the WHERE never matters.
      for (const column of [
        "id",
        '"userOid"',
        '"providerId"',
        '"providerRevision"',
        "env",
        '"grantedAt"',
        '"createdAt"',
        '"updatedAt"',
      ]) {
        await expect(
          pool.query(`UPDATE user_connections SET ${column} = NULL WHERE id = $1`, [connId]),
        ).rejects.toThrow(/permission denied/i);
      }
    } finally {
      await pool.end();
    }
  });

  it("helix_portal holds full DML on all three tables", async () => {
    if (!(await portalRoleAvailable())) return;
    const pool = new Pool({ connectionString: portalUrl(), max: 1 });
    try {
      // The control plane's whole lifecycle on the catalog: create …
      const ref = `rs-portal-${randomUUID().replace(/-/g, "").slice(0, 12)}`;
      await expect(
        pool.query(
          `INSERT INTO connection_providers (id, ref, kind, "displayName", "authorizeEndpoint",
             "tokenEndpoint", "requestedScopes", "apiOrigins", "tokenPlacement", env,
             "clientIdMaterial", "clientSecretMaterial", revision, "createdAt", "updatedAt")
           VALUES (gen_random_uuid(), $1, 'rest-delegated', 'x', 'https://vendor.example/authorize',
             'https://vendor.example/token', '[]'::jsonb, '["https://app.example.com"]'::jsonb,
             '{"kind":"header-bearer"}'::jsonb, 'prod', 'sealed', 'sealed', 1, now(), now())`,
          [ref],
        ),
      ).resolves.toBeDefined();
      await expect(
        pool.query(`UPDATE connection_providers SET "displayName" = 'y' WHERE ref = $1`, [ref]),
      ).resolves.toBeDefined();
      await expect(
        pool.query(`SELECT count(*) FROM connection_providers WHERE ref = $1`, [ref]),
      ).resolves.toBeDefined();
      await expect(
        pool.query(`DELETE FROM connection_providers WHERE ref = $1`, [ref]),
      ).resolves.toBeDefined();

      // … the connections ledger (callback CAS upsert, invalidation, disconnect) …
      await expect(
        pool.query(`UPDATE user_connections SET status = 'invalidated' WHERE "userOid" = $1`, [
          USER,
        ]),
      ).resolves.toBeDefined();

      // … and the consent-flow table (consult writes, cancel, the sweep).
      const attemptId = (
        await pool.query(`SELECT id FROM connection_consent_attempts WHERE "userOid" = $1`, [USER])
      ).rows[0]!.id;
      await expect(
        pool.query(`UPDATE connection_consent_attempts SET "cancelledAt" = now() WHERE id = $1`, [
          attemptId,
        ]),
      ).resolves.toBeDefined();
      await expect(
        pool.query(`DELETE FROM connection_consent_attempts WHERE id = $1`, [attemptId]),
      ).resolves.toBeDefined();
    } finally {
      await pool.end();
    }
  });

  it("env-literal RLS holds per role on the new tables too (dev-mode §5.3)", async () => {
    if (!(await devRoleAvailable())) return;
    // The data-plane roles hold no grant on these tables (asserted above), so
    // "cannot touch the other tier" is enforced at its strongest form —
    // permission denied, not RLS-filtered. The env-LITERAL policies on these
    // tables (helix_edge → 'prod', helix_dev → 'dev') are the second layer
    // that already stands if a future migration ever grants a verb.
    const dev = new Pool({ connectionString: devUrl(), max: 1 });
    const edge = new Pool({ connectionString: edgeUrl(), max: 1 });
    try {
      for (const table of [
        "connection_providers",
        "user_connections",
        "connection_consent_attempts",
      ]) {
        await expect(dev.query(`SELECT count(*) FROM ${table}`)).rejects.toThrow(
          /permission denied/i,
        );
        await expect(edge.query(`SELECT count(*) FROM ${table}`)).rejects.toThrow(
          /permission denied/i,
        );
      }
    } finally {
      await dev.end();
      await edge.end();
    }

    // The roles WITH access: egress legitimately sees both tiers (resolution
    // is keyed (userOid, providerId, env) from the verified instruction —
    // this is the permissive pass doing its job, not a leak), and so does the
    // cross-env control plane. A missing egress policy under FORCE RLS would
    // silently return zero rows here — exactly the failure this catches.
    const egress = new Pool({ connectionString: egressUrl(), max: 1 });
    const portal = new Pool({ connectionString: portalUrl(), max: 1 });
    try {
      const seenByEgress = await egress.query(
        `SELECT env FROM user_connections WHERE "userOid" = $1 AND "providerId" = $2 ORDER BY env`,
        [USER, PROVIDER_ID],
      );
      expect(seenByEgress.rows).toEqual([{ env: "dev" }, { env: "prod" }]);
      const seenByPortal = await portal.query(
        `SELECT env FROM user_connections WHERE "userOid" = $1 AND "providerId" = $2 ORDER BY env`,
        [USER, PROVIDER_ID],
      );
      expect(seenByPortal.rows).toEqual([{ env: "dev" }, { env: "prod" }]);
    } finally {
      await egress.end();
      await portal.end();
    }

    // And the partition label is a CHECK'd vocabulary: no writer can mint an
    // off-value row that every env-literal policy would orphan.
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    try {
      await expect(
        owner.query(
          `INSERT INTO user_connections (id, "userOid", "providerId", "providerRevision", env,
             status, material, "grantedScopes", "grantedAt", "expiresAt", "renewBeforeNext",
             "pendingRetire", "lastRenewedAt", "createdAt", "updatedAt")
           VALUES (gen_random_uuid(), $1, $2, 1, 'staging', 'live', 'x', '[]'::jsonb,
                   now(), now() + interval '1 hour', false, NULL, NULL, now(), now())`,
          [USER, PROVIDER_ID],
        ),
      ).rejects.toThrow(/violates check constraint/i);
    } finally {
      await owner.end();
    }
  });

  it("a provider mutation fires the NOTIFY channel, delivered on commit", async () => {
    if (!(await portalRoleAvailable())) return;
    // A dedicated LISTEN client (never a pool client — the listener pattern
    // the edge's LiveRegistry and egress's future listener copy), receiving
    // the notification the statement-level trigger sends on COMMIT.
    const listener = new Client({ connectionString: TEST_DATABASE_URL });
    const owner = new Pool({ connectionString: TEST_DATABASE_URL, max: 1 });
    try {
      await listener.connect();
      await listener.query(`LISTEN ${PROVIDERS_CHANNEL}`);

      let notified: ((value: { channel: string; payload?: string }) => void) | undefined;
      const notification = new Promise<{ channel: string; payload?: string }>((resolve, reject) => {
        notified = resolve;
        setTimeout(() => reject(new Error("no notification arrived within 5s")), 5000);
      });
      listener.on("notification", (message) => notified?.(message));

      // The mutation commits on a DIFFERENT connection than the listener's —
      // the delivery must ride the trigger + commit, not the same session.
      await owner.query(
        `UPDATE connection_providers SET "displayName" = 'role-split notify' WHERE id = $1`,
        [PROVIDER_ID],
      );

      const received = await notification;
      expect(received.channel).toBe(PROVIDERS_CHANNEL);
      expect(received.payload).toBe("connection_providers");
    } finally {
      listener.removeAllListeners("notification");
      await listener.end();
      await owner.end();
    }
  });
});

describe("app_visits: write-only from the edge, pinned to its partition (ADR-0050)", () => {
  const insert = `INSERT INTO app_visits (id, "appId", env, "visitorHash", "ipPrefix")
                  VALUES (gen_random_uuid(), $1, $2, 'h', '203.0.113.0/24')`;

  async function inPartition(pool: Pool, guc: string | null, sql: string, params: unknown[]) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      if (guc !== null) await client.query("SELECT set_config('app.app_id', $1, true)", [guc]);
      await client.query(sql, params);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  it("helix_edge appends a visit for the request's app and can never read one back", async () => {
    if (!(await edgeRoleAvailable())) return;
    const pool = new Pool({ connectionString: edgeUrl(), max: 1 });
    const appId = randomUUID();
    try {
      // Denials first: after a partition transaction the pooled connection keeps
      // `app.app_id = ''`, and the planner trips on the policy's `''::uuid` cast
      // before the executor's permission check can report the missing grant.
      await expect(pool.query("SELECT count(*) FROM app_visits")).rejects.toThrow(
        /permission denied/i,
      );
      for (const sql of [`UPDATE app_visits SET "ipPrefix" = NULL`, `DELETE FROM app_visits`]) {
        await expect(pool.query(sql)).rejects.toThrow(/permission denied/i);
      }
      await expect(inPartition(pool, appId, insert, [appId, "prod"])).resolves.toBeUndefined();
    } finally {
      await pool.end();
    }
  });

  it("helix_edge's write fails closed with no partition, another app's id, or the dev tier", async () => {
    if (!(await edgeRoleAvailable())) return;
    const pool = new Pool({ connectionString: edgeUrl(), max: 1 });
    const appId = randomUUID();
    try {
      const rls = /row-level security/i;
      await expect(inPartition(pool, null, insert, [appId, "prod"])).rejects.toThrow(rls);
      await expect(inPartition(pool, appId, insert, [randomUUID(), "prod"])).rejects.toThrow(rls);
      await expect(inPartition(pool, appId, insert, [appId, "dev"])).rejects.toThrow(rls);
    } finally {
      await pool.end();
    }
  });

  it("helix_dev and helix_egress have no grant at all", async () => {
    for (const [available, url] of [
      [devRoleAvailable, devUrl],
      [egressRoleAvailable, egressUrl],
    ] as const) {
      if (!(await available())) continue;
      const pool = new Pool({ connectionString: url(), max: 1 });
      try {
        await expect(pool.query("SELECT count(*) FROM app_visits")).rejects.toThrow(
          /permission denied/i,
        );
        await expect(pool.query(insert, [randomUUID(), "prod"])).rejects.toThrow(
          /permission denied/i,
        );
      } finally {
        await pool.end();
      }
    }
  });
});

describe("platform_llm_spend_micro_usd: EXECUTE grant (ADR-0002 amendment)", () => {
  const call = `SELECT * FROM platform_llm_spend_micro_usd('prod')`;

  it("helix_edge can execute the platform spend aggregate", async () => {
    if (!(await edgeRoleAvailable())) return;
    const pool = new Pool({ connectionString: edgeUrl(), max: 1 });
    try {
      await expect(pool.query(call)).resolves.toBeDefined();
    } finally {
      await pool.end();
    }
  });

  it("helix_portal, helix_egress, and helix_dev cannot execute it", async () => {
    for (const [available, url] of [
      [portalRoleAvailable, portalUrl],
      [egressRoleAvailable, egressUrl],
      [devRoleAvailable, devUrl],
    ] as const) {
      if (!(await available())) continue;
      const pool = new Pool({ connectionString: url(), max: 1 });
      try {
        await expect(pool.query(call)).rejects.toThrow(/permission denied/i);
      } finally {
        await pool.end();
      }
    }
  });
});
