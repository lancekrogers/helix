import { randomUUID } from "node:crypto";
import { execSync } from "node:child_process";
import { Pool } from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import {
  ConnectionMaterialSchema,
  ConnectionProviderSchema,
  type ConnectionMaterial,
  type Env,
} from "@azx-pbc/shared";
import {
  ATTR_ENV,
  ATTR_OUTCOME,
  INSTR_EGRESS_RETIREMENTS,
  SPAN_EGRESS_RETIRE,
} from "@azx-pbc/shared/telemetry";
import {
  startDevOAuthVendor,
  requestAuthorizationCode,
  exchangeAuthorizationCode,
  newCodeVerifier,
  s256CodeChallenge,
  type RunningDevOAuthVendor,
} from "@azx-pbc/dev-oauth-vendor";
import { createSecretStore, type SecretStore } from "@azx-pbc/secret-store";
import { CredentialRetirementSweep } from "./retire.js";
import { ConnectionRenewer } from "./renewal.js";
import { createEgressPool } from "./pool.js";
import { makePinnedDispatcher } from "./ssrf.js";
import { EGRESS_SPAN_ATTRS } from "./spanAttributes.js";

/**
 * The credential-retirement sweep (ADR-0031 amendment item 12) against a REAL
 * Postgres (the `helix_egress` grants, including the
 * column-scoped UPDATE the claim and restore ride) and the REAL dev envelope
 * custody. The checklist is the file's structure:
 *
 * - entries seeded through each real writer's marking shape are destroyed and
 *   the field clears — including one end-to-end through the REAL rotating
 *   renewal and the REAL fixture vendor;
 * - a reconnect racing the sweep keeps its new material — a
 *   deterministic interleave, held open by a gated destroy while the writer's
 *   swap commits;
 * - valid connections survive repeated passes;
 * - a forced destroy failure warn-logs the fixed event, counts, restores, and
 *   the retry succeeds;
 * - orphaned material from an interrupted write is retired;
 * - start/stop cycles release the timer and the in-flight pass.
 *
 * **Its own database, not the shared `helix_test`.** The sweep is the first
 * cross-cutting consumer in the suite: a pass destroys EVERY ledger-marked
 * row it finds, and the suite's other integration files (renewal, delegated,
 * the portal's) hold `pendingRetire` marks their tests assert on — a pass
 * running concurrently with those files would consume marks out from under
 * their write→assert windows. So this file clones the migrated schema into a
 * dedicated database for its own lifetime (the globalSetup's migrate-deploy
 * step, pointed at a scratch database; ~1s), and drops it after. Skips
 * fail-soft — like the other integration suites' role-provisioned skip —
 * when the DB isn't reachable or the clone can't be built.
 */

const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? "postgresql://helix:helix@db:5432/helix_test";

const RETIRE_DB = "helix_retire_test";
const RETIRE_DATABASE_URL = TEST_DATABASE_URL.replace(/\/[^/]+$/, `/${RETIRE_DB}`);

function egressUrl(): string {
  const u = new URL(RETIRE_DATABASE_URL);
  u.username = "helix_egress";
  u.password = "helix_egress";
  return u.toString();
}

const REDIRECT_URI = "https://auth.local.helix.azxlabs.io/connections/callback";
const RETIRE_CLIENT_ID = "retire-fixture-client";
const RETIRE_CLIENT_SECRET = "retire-fixture-secret-52cd";

let ok = false;

beforeAll(async () => {
  const adminUrl = TEST_DATABASE_URL.replace(/\/[^/]+$/, "/helix");
  try {
    execSync(`psql "${adminUrl}" -c "DROP DATABASE IF EXISTS ${RETIRE_DB} WITH (FORCE)"`, {
      stdio: "pipe",
    });
    execSync(`psql "${adminUrl}" -c "CREATE DATABASE ${RETIRE_DB}"`, { stdio: "pipe" });
    execSync("pnpm --filter @azx-pbc/portal exec prisma migrate deploy", {
      stdio: "pipe",
      env: { ...process.env, DATABASE_URL: RETIRE_DATABASE_URL },
    });
  } catch (err) {
    console.warn("[retire.integration] dedicated test database unavailable; skipping", err);
    return;
  }
  // The grants ride the migration's role-conditional blocks: without the
  // provisioned roles (CI without db-init) the egress identity connects to
  // nothing — the same fail-soft skip the other integration suites take.
  const probe = new Pool({ connectionString: egressUrl(), max: 1 });
  try {
    await probe.query("SELECT 1");
    ok = true;
  } catch {
    ok = false;
  } finally {
    await probe.end();
  }
});

afterAll(async () => {
  if (!ok) return;
  const adminUrl = TEST_DATABASE_URL.replace(/\/[^/]+$/, "/helix");
  try {
    execSync(`psql "${adminUrl}" -c "DROP DATABASE ${RETIRE_DB} WITH (FORCE)"`, { stdio: "pipe" });
  } catch {
    // A dropped-later scratch database is not a test failure.
  }
});

const recording: RecordingTelemetry = startRecordingTelemetry();

const kek = Buffer.from("retire-test-kek-0123456789abcdef", "utf8");
const inner = createSecretStore({ devMasterKey: kek });

/**
 * The delegated store with observable custody: the dev envelope's `destroy`
 * is a no-op by design (the ciphertext lives in the row), so observability is
 * the destroy call itself. The wrapper also injects the two test faults the
 * checklist needs — a failing destroy (visibility + retry) and
 * a gate that holds one destroy open while the test commits a writer's swap
 * (the interleave). The gate is checked BEFORE the failure
 * injection, so a parked destroy can complete and the NEXT call can fail.
 */
const destroyed: string[] = [];
let failuresLeft = 0;
let gate: {
  match: string;
  enteredResolve: () => void;
  opened: Promise<void>;
  release: () => void;
} | null = null;

const delegated: SecretStore = {
  seal: (value) => inner.seal(value),
  open: (material) => inner.open(material),
  destroy: async (material) => {
    if (gate && material.includes(gate.match)) {
      gate.enteredResolve();
      await gate.opened;
    }
    if (failuresLeft > 0) {
      failuresLeft--;
      throw new Error("forced destroy failure");
    }
    destroyed.push(material);
  },
};

/** Arm the gate: the next destroy of material containing `match` blocks. */
function armGate(match: string): Promise<void> {
  let enteredResolve: () => void = () => {};
  const entered = new Promise<void>((r) => (enteredResolve = r));
  let release: () => void = () => {};
  const opened = new Promise<void>((r) => (release = r));
  gate = { match, enteredResolve, opened, release };
  return entered;
}

function releaseGate(): void {
  gate?.release();
  gate = null;
}

/** The captured warn stream — the fixed `egress.connection_retire_failed` event. */
const warnings: Array<Record<string, unknown>> = [];
const log = { warn: (obj: Record<string, unknown>, msg: string) => warnings.push({ ...obj, msg }) };

let pool: ReturnType<typeof createEgressPool> | undefined;
let sweep: CredentialRetirementSweep | undefined;

beforeAll(() => {
  if (!ok) return;
  pool = createEgressPool(egressUrl(), { max: 4 });
  sweep = new CredentialRetirementSweep({
    pool,
    delegatedStore: delegated,
    intervalMs: 60_000,
    log,
  });
});

const seededIds: string[] = [];

afterAll(async () => {
  await recording.restore();
  await pool?.end();
});

afterEach(async () => {
  // The adversarial scan (the spanAttributes suite's extension to this
  // operation): EVERY attribute of EVERY span is allowlisted, no egress span
  // records an exception, and none of the plaintext this suite plants appears
  // in any recorded attribute.
  for (const span of recording.spans()) {
    for (const key of Object.keys(span.attributes)) {
      expect(EGRESS_SPAN_ATTRS, `${span.name} carried ${key}`).toContain(key);
    }
    expect(span.events.filter((e) => e.name === "exception")).toEqual([]);
    expect(JSON.stringify(span.attributes)).not.toMatch(/retire-plain-(access|refresh)/);
  }
  recording.reset();
  failuresLeft = 0;
  releaseGate();
  destroyed.length = 0;
  warnings.length = 0;
  if (ok) await deleteSeededRows();
});

async function ownerQuery<T extends Record<string, unknown>>(
  sql: string,
  values: unknown[] = [],
): Promise<T[]> {
  const owner = new Pool({ connectionString: RETIRE_DATABASE_URL, max: 1 });
  try {
    return (await owner.query<T>(sql, values)).rows;
  } finally {
    await owner.end();
  }
}

/** Seal one plaintext pair into the envelope shape every writer stores. */
async function sealEnvelope(tokens: { access: string; refresh: string }): Promise<string> {
  return JSON.stringify(
    ConnectionMaterialSchema.parse({
      access: await delegated.seal(tokens.access),
      refresh: await delegated.seal(tokens.refresh),
    }),
  );
}

/**
 * Seed one connection row (as the owner). `pendingRetire` is the ledger mark
 * in exactly the shape the named writer leaves it; `material` the row's
 * current envelope.
 */
async function seedConnection(opts: {
  userOid?: string;
  env?: Env;
  status?: "live" | "reconnect-needed" | "invalidated";
  providerId?: string;
  material: string;
  pendingRetire?: string | null;
}): Promise<{ id: string; userOid: string; env: Env }> {
  const id = randomUUID();
  const userOid = opts.userOid ?? `retire-user-${randomUUID()}`;
  const env = opts.env ?? "prod";
  await ownerQuery(
    `INSERT INTO user_connections (id, "userOid", "providerId", "providerRevision", env, status,
        material, "grantedScopes", "grantedAt", "expiresAt", "renewBeforeNext", "pendingRetire",
        "lastRenewedAt", "createdAt", "updatedAt")
      VALUES ($1::uuid, $2, $3::uuid, 1, $4, $5, $6, '[]'::jsonb, now(),
              now() + interval '1 hour', false, $7, NULL, now(), now())`,
    [
      id,
      userOid,
      opts.providerId ?? randomUUID(),
      env,
      opts.status ?? "live",
      opts.material,
      opts.pendingRetire ?? null,
    ],
  );
  seededIds.push(id);
  return { id, userOid, env };
}

/**
 * Per-test isolation: each test deletes the rows it seeded, so a failed test
 * cannot leak a marked row into a later test's pass — the sweep consumes
 * whatever the ledger holds, and a stale mark would pollute the next test's
 * `destroyed` set and metric deltas.
 */
async function deleteSeededRows(): Promise<void> {
  if (seededIds.length === 0) return;
  await ownerQuery(`DELETE FROM user_connections WHERE id = ANY($1::uuid[])`, [seededIds]);
  seededIds.length = 0;
}

/**
 * The pass's read order for these ids — Postgres's own `ORDER BY id`, the one
 * authority for which row a parked pass reaches first (a JS string sort is a
 * guess about someone else's collation).
 */
async function sweepOrder(ids: string[]): Promise<string[]> {
  const rows = await ownerQuery<{ id: string }>(
    `SELECT id FROM user_connections WHERE id = ANY($1::uuid[]) ORDER BY id`,
    [ids],
  );
  return rows.map((r) => r.id);
}

/** Read one row's ledger + material fields back through the egress identity. */
async function readRow(
  id: string,
): Promise<{ material: string; pendingRetire: string | null } | null> {
  const rows = await pool!.query<{ material: string; pendingRetire: string | null }>(
    `SELECT material, "pendingRetire" FROM user_connections WHERE id = $1::uuid`,
    [id],
  );
  return rows.rows[0] ?? null;
}

async function metricTotal(name: string, match: Record<string, string>): Promise<number> {
  const points = await recording.metrics();
  return points
    .filter(
      (m) => m.name === name && Object.entries(match).every(([k, v]) => m.attributes[k] === v),
    )
    .reduce((sum, m) => sum + m.value, 0);
}

describe("CredentialRetirementSweep (helix_egress)", () => {
  it("destroys and clears a ledger-marked entry seeded through each real writer's marking shape", async () => {
    if (!ok) return;
    // The four writers' shapes, verbatim from each writer's SQL:
    // - lost callback race (completion.ts): the row that beat the
    //   loser stays live; the LOSER's own material is ledger-marked on it.
    // - rotating renewal (renewal.ts): the swap writes the OLD
    //   envelope beside the NEW material in the same UPDATE.
    // - disconnect (connectionsMine.ts) and sensitive-edit
    //   invalidation (providers.ts): both invalidate the row and mark
    //   its OWN material in the same UPDATE — identical shapes by design.
    const cases: Array<{
      writer: string;
      status: "live" | "reconnect-needed" | "invalidated";
      materialTokens: { access: string; refresh: string };
      markedTokens: { access: string; refresh: string };
    }> = [
      {
        writer: "lost callback race",
        status: "live",
        materialTokens: { access: "retire-plain-access", refresh: "retire-plain-refresh" },
        markedTokens: { access: "loser-callback-access", refresh: "loser-callback-refresh" },
      },
      {
        writer: "rotating renewal",
        status: "live",
        materialTokens: { access: "rotated-new-access", refresh: "rotated-new-refresh" },
        markedTokens: { access: "rotated-old-access", refresh: "rotated-old-refresh" },
      },
      {
        writer: "disconnect",
        status: "invalidated",
        materialTokens: { access: "disconnected-access", refresh: "disconnected-refresh" },
        markedTokens: { access: "disconnected-access", refresh: "disconnected-refresh" },
      },
      {
        writer: "sensitive-edit invalidation",
        status: "invalidated",
        materialTokens: { access: "invalidated-access", refresh: "invalidated-refresh" },
        markedTokens: { access: "invalidated-access", refresh: "invalidated-refresh" },
      },
    ];

    const seeded = new Array<{ id: string; marked: ConnectionMaterial }>();
    for (const c of cases) {
      const marked = ConnectionMaterialSchema.parse(JSON.parse(await sealEnvelope(c.markedTokens)));
      const row = await seedConnection({
        status: c.status,
        material: await sealEnvelope(c.materialTokens),
        pendingRetire: JSON.stringify(marked),
      });
      seeded.push({ id: row.id, marked });
    }

    await sweep!.sweepOnce();

    for (const [i, c] of cases.entries()) {
      const { id, marked } = seeded[i]!;
      expect(destroyed, c.writer).toContain(marked.access);
      expect(destroyed, c.writer).toContain(marked.refresh);
      const after = await readRow(id);
      expect(after?.pendingRetire, c.writer).toBeNull();
    }
  });

  it("retires what a REAL rotating renewal marked, and the new material still opens", async () => {
    if (!ok) return;
    const vendor: RunningDevOAuthVendor = await startDevOAuthVendor({
      accessTokenTtlSeconds: 900,
      clientId: RETIRE_CLIENT_ID,
      clientSecret: RETIRE_CLIENT_SECRET,
    });
    try {
      // A real provider row (sealed client credentials) + a real expired
      // connection sealed under the same KEK — the renewal's inputs.
      const provider = ConnectionProviderSchema.parse({
        id: randomUUID(),
        ref: `retire-fixture-${randomUUID().replaceAll("-", "").slice(0, 12)}`,
        kind: "rest-delegated",
        displayName: "Retirement Fixture",
        authorizeEndpoint: `${vendor.issuer}/authorize`,
        tokenEndpoint: `${vendor.issuer}/token`,
        requestedScopes: [],
        apiOrigins: ["https://api.fixture.test"],
        tokenPlacement: { kind: "header-bearer" },
        env: "prod",
        clientIdMaterial: await inner.seal(RETIRE_CLIENT_ID),
        clientSecretMaterial: await inner.seal(RETIRE_CLIENT_SECRET),
        revision: 1,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
      await ownerQuery(
        `INSERT INTO connection_providers (id, ref, kind, "displayName", "authorizeEndpoint",
            "tokenEndpoint", "requestedScopes", "apiOrigins", "tokenPlacement", env,
            "clientIdMaterial", "clientSecretMaterial", revision, "createdAt", "updatedAt")
          VALUES ($1::uuid, $2, 'rest-delegated', 'Retirement Fixture', $3, $4, '[]'::jsonb,
                  '["https://api.fixture.test"]'::jsonb, '{"kind":"header-bearer"}'::jsonb,
                  'prod', $5, $6, 1, now(), now())`,
        [
          provider.id,
          provider.ref,
          provider.authorizeEndpoint,
          provider.tokenEndpoint,
          provider.clientIdMaterial,
          provider.clientSecretMaterial,
        ],
      );

      const verifier = newCodeVerifier();
      const auth = await requestAuthorizationCode(vendor, {
        redirectUri: REDIRECT_URI,
        challenge: s256CodeChallenge(verifier),
        clientId: RETIRE_CLIENT_ID,
      });
      const exchanged = await exchangeAuthorizationCode(vendor, auth.code as string, {
        verifier,
        redirectUri: REDIRECT_URI,
        clientId: RETIRE_CLIENT_ID,
        clientSecret: RETIRE_CLIENT_SECRET,
      });
      expect(exchanged.ok).toBe(true);
      const tokens = {
        access: exchanged.body.access_token as string,
        refresh: exchanged.body.refresh_token as string,
      };
      const oldEnvelope = ConnectionMaterialSchema.parse(JSON.parse(await sealEnvelope(tokens)));
      const row = await seedConnection({
        providerId: provider.id,
        material: JSON.stringify(oldEnvelope),
      });
      // Expired, so the renewal is due.
      await ownerQuery(
        `UPDATE user_connections SET "expiresAt" = now() - interval '1 minute' WHERE id = $1::uuid`,
        [row.id],
      );

      // The REAL writer: a rotating renewal through the renewer —
      // vendor round-trip, rotation, and the ledger mark in the swap's UPDATE.
      const renewer = new ConnectionRenewer({
        pool: pool!,
        providers: {
          get: (id: string) => (id === provider.id ? provider : undefined),
          getByRef: () => provider,
          isLoaded: () => true,
        },
        credentialStore: inner,
        delegatedStore: delegated,
        dispatcher: makePinnedDispatcher(true, 1_000, []),
        timeoutMs: 1_000,
        allowInsecureConnection: true,
      });
      const renewed = await renewer.renew({
        userOid: row.userOid,
        providerId: provider.id,
        env: "prod",
      });
      expect(renewed.outcome).toBe("refreshed");

      const marked = await readRow(row.id);
      expect(marked?.pendingRetire).not.toBeNull();
      expect(marked?.pendingRetire).not.toBe(marked?.material);
      const oldMarked = ConnectionMaterialSchema.parse(JSON.parse(marked!.pendingRetire!));
      const newMaterial = ConnectionMaterialSchema.parse(JSON.parse(marked!.material));

      await sweep!.sweepOnce();

      // The OLD envelope is destroyed and the field clears…
      expect(destroyed).toContain(oldMarked.access);
      expect(destroyed).toContain(oldMarked.refresh);
      const after = await readRow(row.id);
      expect(after?.pendingRetire).toBeNull();
      // …and the CURRENT material is intact and still opens.
      // (The renewed access token is the vendor's FRESH one, not the original.)
      expect(after?.material).toBe(marked?.material);
      expect(await inner.open(newMaterial.access)).toBe(renewed.accessToken);
    } finally {
      await vendor.close();
    }
  });

  it("a reconnect racing the sweep keeps its new material: the claim loses, nothing of the new reference is destroyed", async () => {
    if (!ok) return;
    // Row A parks the pass on a gated destroy (its claim already won); row B
    // holds a renewal-CAS-loss orphan mark (renewal.ts's shape). While the
    // pass is parked, B's reconnect swap commits — material = NEW,
    // pendingRetire = the row's pre-swap material, exactly the completion.ts
    // DO UPDATE — replacing B's mark. B's claim must then LOSE: the mark it
    // read is gone, no destroy fires for anything B now names, and the
    // writer's own OLD-reference mark is consumed by the next pass.
    // The pass reads rows ordered by id, so the test casts the two rows by
    // id order: the smaller id parks the pass, the larger is raced.
    const parkedEnv = ConnectionMaterialSchema.parse(
      JSON.parse(await sealEnvelope({ access: "parked-access", refresh: "parked-refresh" })),
    );
    const racedOld = ConnectionMaterialSchema.parse(
      JSON.parse(await sealEnvelope({ access: "raced-old-access", refresh: "raced-old-refresh" })),
    );
    const reconnectNew = ConnectionMaterialSchema.parse(
      JSON.parse(
        await sealEnvelope({ access: "reconnect-new-access", refresh: "reconnect-new-refresh" }),
      ),
    );
    const orphan = ConnectionMaterialSchema.parse(
      JSON.parse(await sealEnvelope({ access: "orphan-access", refresh: "orphan-refresh" })),
    );

    // Seed two placeholder rows, then cast them into their roles by the
    // sweep's own read order: the smaller id parks the pass, the larger is
    // raced by the reconnect.
    const a = await seedConnection({ status: "invalidated", material: "x", pendingRetire: null });
    const b = await seedConnection({ status: "invalidated", material: "x", pendingRetire: null });
    const order = await sweepOrder([a.id, b.id]);
    const parkedId = order[0]!;
    const racedId = order[1]!;
    await ownerQuery(
      `UPDATE user_connections SET material = $2, "pendingRetire" = $2 WHERE id = $1::uuid`,
      [parkedId, JSON.stringify(parkedEnv)],
    );
    await ownerQuery(
      `UPDATE user_connections SET material = $2, "pendingRetire" = $3 WHERE id = $1::uuid`,
      [racedId, JSON.stringify(racedOld), JSON.stringify(orphan)],
    );
    const rowA = { id: parkedId };
    const rowB = { id: racedId };

    const entered = armGate(parkedEnv.access);
    const pass = sweep!.sweepOnce();
    await entered;

    // The reconnect's swap (the completion.ts DO UPDATE shape) commits while
    // the sweep is parked on row A's destroy: the mark the sweep READ (the
    // orphan) is replaced before the sweep reaches row B's claim. The swap
    // re-marks the row's PRE-SWAP material (racedOld) as its ledger entry.
    await ownerQuery(
      `UPDATE user_connections SET status = 'live', material = $2,
          "pendingRetire" = $3, "providerRevision" = 1, "grantedAt" = now(),
          "expiresAt" = now() + interval '1 hour', "renewBeforeNext" = false,
          "lastRenewedAt" = NULL, "updatedAt" = now()
        WHERE id = $1::uuid`,
      [rowB.id, JSON.stringify(reconnectNew), JSON.stringify(racedOld)],
    );

    releaseGate();
    await pass;

    // A: claimed + destroyed, cleared.
    expect(destroyed).toContain(parkedEnv.access);
    expect(destroyed).toContain(parkedEnv.refresh);
    expect((await readRow(rowA.id))?.pendingRetire).toBeNull();

    // B: the claim LOST — no destroy fired AT ALL for row B this pass (not
    // the stale orphan mark it read, not the writer's re-mark, never the NEW
    // reference), and the reconnect's ledger entry survives for a later pass.
    expect(destroyed).not.toContain(orphan.access);
    expect(destroyed).not.toContain(orphan.refresh);
    expect(destroyed).not.toContain(reconnectNew.access);
    expect(destroyed).not.toContain(reconnectNew.refresh);
    expect(destroyed).not.toContain(racedOld.access);
    expect(destroyed).not.toContain(racedOld.refresh);
    const afterB = await readRow(rowB.id);
    expect(afterB?.material).toBe(JSON.stringify(reconnectNew));
    expect(afterB?.pendingRetire).toBe(JSON.stringify(racedOld));
    expect(await inner.open(reconnectNew.access)).toBe("reconnect-new-access");

    // The next pass consumes the writer's own mark — and STILL never the
    // current connection's material.
    await sweep!.sweepOnce();
    expect(destroyed).toContain(racedOld.access);
    expect(destroyed).toContain(racedOld.refresh);
    expect(destroyed).not.toContain(reconnectNew.access);
    expect(destroyed).not.toContain(reconnectNew.refresh);
    const settled = await readRow(rowB.id);
    expect(settled?.pendingRetire).toBeNull();
    expect(settled?.material).toBe(JSON.stringify(reconnectNew));
  });

  it("a reconnect racing a matching mark destroys only the OLD reference, never the new", async () => {
    if (!ok) return;
    // The other interleave: the sweep's read mark IS the reconnect's
    // re-marked reference (a disconnect marked the row's own material, and
    // the reconnect's swap re-marks exactly that as pendingRetire). The claim
    // then WINS — and destroys the OLD material the mark names, while the NEW
    // material comes out untouched.
    const oldEnv = ConnectionMaterialSchema.parse(
      JSON.parse(
        await sealEnvelope({ access: "matched-old-access", refresh: "matched-old-refresh" }),
      ),
    );
    const newEnv = ConnectionMaterialSchema.parse(
      JSON.parse(
        await sealEnvelope({ access: "matched-new-access", refresh: "matched-new-refresh" }),
      ),
    );
    const row = await seedConnection({
      status: "invalidated",
      material: JSON.stringify(oldEnv),
      pendingRetire: JSON.stringify(oldEnv),
    });

    const entered = armGate(oldEnv.access);
    const pass = sweep!.sweepOnce();
    await entered;
    // The reconnect commits while the sweep holds the claim, before the
    // destroy completes: the swap re-marks the same OLD reference, so the
    // row's ledger reads the OLD reference again afterwards.
    await ownerQuery(
      `UPDATE user_connections SET status = 'live', material = $2,
          "pendingRetire" = $3, "providerRevision" = 1, "grantedAt" = now(),
          "expiresAt" = now() + interval '1 hour', "renewBeforeNext" = false,
          "lastRenewedAt" = NULL, "updatedAt" = now()
        WHERE id = $1::uuid`,
      [row.id, JSON.stringify(newEnv), JSON.stringify(oldEnv)],
    );
    releaseGate();
    await pass;

    expect(destroyed).toContain(oldEnv.access);
    expect(destroyed).toContain(oldEnv.refresh);
    expect(destroyed).not.toContain(newEnv.access);
    expect(destroyed).not.toContain(newEnv.refresh);
    const after = await readRow(row.id);
    expect(after?.material).toBe(JSON.stringify(newEnv));
    expect(after?.pendingRetire).toBe(JSON.stringify(oldEnv));
    expect(await inner.open(newEnv.access)).toBe("matched-new-access");

    // The writer's re-mark is consumed by the next pass: the same OLD
    // reference destroyed again (idempotent — the Key Vault store treats
    // already-gone as the goal), the NEW reference still never touched.
    await sweep!.sweepOnce();
    expect(destroyed).toContain(oldEnv.access);
    expect(destroyed).not.toContain(newEnv.access);
    expect(await readRow(row.id)).toMatchObject({
      pendingRetire: null,
      material: JSON.stringify(newEnv),
    });
  });

  it("valid connections with no ledger marks survive repeated passes", async () => {
    if (!ok) return;
    const liveMaterial = await sealEnvelope({
      access: "survivor-access",
      refresh: "survivor-refresh",
    });
    const expiredMaterial = await sealEnvelope({
      access: "survivor2-access",
      refresh: "survivor2-refresh",
    });
    const live = await seedConnection({ status: "live", material: liveMaterial });
    const expired = await seedConnection({ status: "live", material: expiredMaterial });
    await ownerQuery(
      `UPDATE user_connections SET "expiresAt" = now() - interval '1 hour' WHERE id = $1::uuid`,
      [expired.id],
    );

    for (let i = 0; i < 3; i++) {
      await sweep!.sweepOnce();
    }

    expect(destroyed).toEqual([]);
    const liveAfter = await readRow(live.id);
    expect(liveAfter?.material).toBe(liveMaterial);
    expect(liveAfter?.pendingRetire).toBeNull();
    const expiredAfter = await readRow(expired.id);
    expect(expiredAfter?.material).toBe(expiredMaterial);
    expect(expiredAfter?.pendingRetire).toBeNull();
  });

  it("a forced destroy failure warn-logs the fixed event, counts, restores the mark, and the retry succeeds", async () => {
    if (!ok) return;
    const marked = ConnectionMaterialSchema.parse(
      JSON.parse(await sealEnvelope({ access: "flaky-access", refresh: "flaky-refresh" })),
    );
    const row = await seedConnection({
      status: "invalidated",
      material: JSON.stringify(marked),
      pendingRetire: JSON.stringify(marked),
    });

    failuresLeft = 1;
    await sweep!.sweepOnce();

    // Nothing was destroyed, the fixed event fired with bounded metadata, the
    // counter counted, and the ledger entry is BACK — retriable, no operator.
    expect(destroyed).toEqual([]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({
      event: "egress.connection_retire_failed",
      connectionId: row.id,
      env: "prod",
      reason: "destroy_failed",
    });
    expect(warnings[0]!.providerRef).toBeUndefined();
    expect(JSON.stringify(warnings[0])).not.toContain("aesgcm:");
    const failedBefore = await metricTotal(INSTR_EGRESS_RETIREMENTS, {
      [ATTR_OUTCOME]: "failed",
      [ATTR_ENV]: "prod",
    });
    expect(failedBefore).toBeGreaterThanOrEqual(1);
    const restored = await readRow(row.id);
    expect(restored?.pendingRetire).toBe(JSON.stringify(marked));

    // The fault clears; the very next pass retires the entry.
    await sweep!.sweepOnce();
    expect(destroyed).toContain(marked.access);
    expect(destroyed).toContain(marked.refresh);
    const settled = await readRow(row.id);
    expect(settled?.pendingRetire).toBeNull();
  });

  it("a destroy failure whose restore loses the slot is said at the same fixed event, and the writer's mark governs", async () => {
    if (!ok) return;
    // A writer re-purposed the slot between the claim and the restore: the
    // restore's `IS NULL` predicate matches nothing, the writer's mark
    // governs, and the failure is still visible without
    // clobbering the newer reference.
    const marked = ConnectionMaterialSchema.parse(
      JSON.parse(
        await sealEnvelope({ access: "restore-race-access", refresh: "restore-race-refresh" }),
      ),
    );
    const newer = ConnectionMaterialSchema.parse(
      JSON.parse(
        await sealEnvelope({ access: "newer-mark-access", refresh: "newer-mark-refresh" }),
      ),
    );
    const row = await seedConnection({
      status: "invalidated",
      material: JSON.stringify(marked),
      pendingRetire: JSON.stringify(marked),
    });

    failuresLeft = 1;
    const entered = armGate(marked.access);
    const pass = sweep!.sweepOnce();
    await entered;
    await ownerQuery(`UPDATE user_connections SET "pendingRetire" = $2 WHERE id = $1::uuid`, [
      row.id,
      JSON.stringify(newer),
    ]);
    releaseGate();
    await pass;

    // The FIRST destroy (access) parked on the gate and then failed (the
    // wrapper injects the failure after the gate) — so nothing of this
    // entry's was destroyed; the restore found the slot taken by the
    // writer's newer mark.
    expect(destroyed).not.toContain(marked.access);
    expect(destroyed).not.toContain(marked.refresh);
    expect(warnings[0]).toMatchObject({
      event: "egress.connection_retire_failed",
      connectionId: row.id,
      reason: "ledger_slot_taken",
    });
    const after = await readRow(row.id);
    expect(after?.pendingRetire).toBe(JSON.stringify(newer));

    // The writer's mark is consumed by the next pass; the failed reference's
    // remaining half is the accepted single-slot residual.
    await sweep!.sweepOnce();
    expect(destroyed).toContain(newer.access);
    expect(destroyed).toContain(newer.refresh);
    expect(await readRow(row.id)).toMatchObject({ pendingRetire: null });
  });

  it("retires credentials orphaned by an interrupted seal→write (a ledger entry exists)", async () => {
    if (!ok) return;
    // The crash was "recovered" — the sweep's next pass finds the ledger
    // entry. The orphan envelope is referenced by NOTHING (no row's material
    // points at it); the row's own current material is never touched.
    const orphan = ConnectionMaterialSchema.parse(
      JSON.parse(await sealEnvelope({ access: "stranded-access", refresh: "stranded-refresh" })),
    );
    const current = ConnectionMaterialSchema.parse(
      JSON.parse(await sealEnvelope({ access: "current-access", refresh: "current-refresh" })),
    );
    const row = await seedConnection({
      status: "reconnect-needed",
      material: JSON.stringify(current),
      pendingRetire: JSON.stringify(orphan),
    });

    await sweep!.sweepOnce();

    expect(destroyed).toContain(orphan.access);
    expect(destroyed).toContain(orphan.refresh);
    expect(destroyed).not.toContain(current.access);
    expect(destroyed).not.toContain(current.refresh);
    const after = await readRow(row.id);
    expect(after?.pendingRetire).toBeNull();
    expect(after?.material).toBe(JSON.stringify(current));
  });

  it("counts retired, failed and claimed_lost outcomes with bounded dimensions", async () => {
    if (!ok) return;
    const marked = ConnectionMaterialSchema.parse(
      JSON.parse(await sealEnvelope({ access: "counted-access", refresh: "counted-refresh" })),
    );
    const devMarked = ConnectionMaterialSchema.parse(
      JSON.parse(
        await sealEnvelope({ access: "counted-dev-access", refresh: "counted-dev-refresh" }),
      ),
    );
    const parkedEnv = ConnectionMaterialSchema.parse(
      JSON.parse(
        await sealEnvelope({ access: "counted-parked-access", refresh: "counted-parked-refresh" }),
      ),
    );
    const replaced = ConnectionMaterialSchema.parse(
      JSON.parse(await sealEnvelope({ access: "replaced-access", refresh: "replaced-refresh" })),
    );
    const orphan = ConnectionMaterialSchema.parse(
      JSON.parse(
        await sealEnvelope({ access: "counted-orphan-access", refresh: "counted-orphan-refresh" }),
      ),
    );

    const retiredRow = await seedConnection({
      status: "invalidated",
      material: JSON.stringify(marked),
      pendingRetire: JSON.stringify(marked),
    });
    const devRow = await seedConnection({
      env: "dev",
      status: "invalidated",
      material: JSON.stringify(devMarked),
      pendingRetire: JSON.stringify(devMarked),
    });
    // The claim that loses needs a writer to re-purpose the mark BETWEEN the
    // sweep's read and its claim: the pass is parked on the row whose id
    // sorts first, the raced row (mark = orphan) is re-marked while parked,
    // and its claim then matches zero rows. Roles are cast by the sweep's own
    // read order.
    const a = await seedConnection({ status: "invalidated", material: "x", pendingRetire: null });
    const b = await seedConnection({ status: "invalidated", material: "x", pendingRetire: null });
    const order = await sweepOrder([a.id, b.id]);
    const parkedId = order[0]!;
    const racedId = order[1]!;
    await ownerQuery(
      `UPDATE user_connections SET material = $2, "pendingRetire" = $2 WHERE id = $1::uuid`,
      [parkedId, JSON.stringify(parkedEnv)],
    );
    await ownerQuery(
      `UPDATE user_connections SET material = $2, "pendingRetire" = $3 WHERE id = $1::uuid`,
      [racedId, JSON.stringify(replaced), JSON.stringify(orphan)],
    );

    const retiredBefore = await metricTotal(INSTR_EGRESS_RETIREMENTS, {
      [ATTR_OUTCOME]: "retired",
      [ATTR_ENV]: "prod",
    });
    const lostBefore = await metricTotal(INSTR_EGRESS_RETIREMENTS, {
      [ATTR_OUTCOME]: "claimed_lost",
      [ATTR_ENV]: "prod",
    });
    const devRetiredBefore = await metricTotal(INSTR_EGRESS_RETIREMENTS, {
      [ATTR_OUTCOME]: "retired",
      [ATTR_ENV]: "dev",
    });

    const entered = armGate(parkedEnv.access);
    const pass = sweep!.sweepOnce();
    await entered;
    await ownerQuery(`UPDATE user_connections SET "pendingRetire" = $2 WHERE id = $1::uuid`, [
      racedId,
      JSON.stringify(replaced),
    ]);
    releaseGate();
    await pass;

    expect(
      (await metricTotal(INSTR_EGRESS_RETIREMENTS, {
        [ATTR_OUTCOME]: "retired",
        [ATTR_ENV]: "prod",
      })) - retiredBefore,
    ).toBe(2); // the parked row + the plain marked row
    expect(
      (await metricTotal(INSTR_EGRESS_RETIREMENTS, {
        [ATTR_OUTCOME]: "claimed_lost",
        [ATTR_ENV]: "prod",
      })) - lostBefore,
    ).toBe(1); // the raced row's stale orphan claim
    expect(
      (await metricTotal(INSTR_EGRESS_RETIREMENTS, {
        [ATTR_OUTCOME]: "retired",
        [ATTR_ENV]: "dev",
      })) - devRetiredBefore,
    ).toBe(1);
    expect(await readRow(retiredRow.id)).toMatchObject({ pendingRetire: null });
    expect(await readRow(devRow.id)).toMatchObject({ pendingRetire: null });
    // The lost claim left the writer's newer mark untouched for a later pass.
    expect(await readRow(racedId)).toMatchObject({ pendingRetire: JSON.stringify(replaced) });
    expect(destroyed).not.toContain(replaced.access);
    // The pass span exists, on the bounded vocabulary.
    expect(recording.spans().some((s) => s.name === SPAN_EGRESS_RETIRE)).toBe(true);
  });

  it("repeated start/stop cycles release the timer and await the in-flight pass", async () => {
    if (!ok) return;
    // A dedicated pool + sweep: the release proof is that `pool.end()`
    // resolves with nothing checked out and the timer gone.
    const lifecyclePool = createEgressPool(egressUrl(), { max: 2 });
    const lifecycleSweep = new CredentialRetirementSweep({
      pool: lifecyclePool,
      delegatedStore: delegated,
      intervalMs: 10,
      log,
    });

    // 1. stop() waits out an in-flight pass held open by the gate.
    const marked = ConnectionMaterialSchema.parse(
      JSON.parse(await sealEnvelope({ access: "lifecycle-access", refresh: "lifecycle-refresh" })),
    );
    const row = await seedConnection({
      status: "invalidated",
      material: JSON.stringify(marked),
      pendingRetire: JSON.stringify(marked),
    });
    const entered = armGate(marked.access);
    lifecycleSweep.start();
    await entered;
    let stopped = false;
    const stopping = lifecycleSweep.stop().then(() => (stopped = true));
    await new Promise((r) => setTimeout(r, 30));
    expect(stopped).toBe(false); // still parked on the in-flight destroy
    releaseGate();
    await stopping;
    expect(destroyed).toContain(marked.access);
    expect(await readRow(row.id)).toMatchObject({ pendingRetire: null });

    // 2. Repeated cycles each run a pass; nothing leaks between them.
    for (let cycle = 0; cycle < 3; cycle++) {
      const cycleMarked = ConnectionMaterialSchema.parse(
        JSON.parse(
          await sealEnvelope({
            access: `cycle-${cycle}-access`,
            refresh: `cycle-${cycle}-refresh`,
          }),
        ),
      );
      await seedConnection({
        status: "invalidated",
        material: JSON.stringify(cycleMarked),
        pendingRetire: JSON.stringify(cycleMarked),
      });
      lifecycleSweep.start();
      await vi.waitFor(() => expect(destroyed).toContain(cycleMarked.access));
      await lifecycleSweep.stop();
    }
    // After the last stop, no further pass may fire.
    const afterStop = destroyed.length;
    await new Promise((r) => setTimeout(r, 40));
    expect(destroyed.length).toBe(afterStop);

    await lifecyclePool.end(); // resolves: no client left checked out
  });

  it("runs inert with no telemetry provider registered (the OTEL_SDK_DISABLED=1 posture)", async () => {
    if (!ok) return;
    // Restore the recording first: with no provider registered, the counter
    // rides @opentelemetry/api's no-op facade — the sweep must neither fail
    // nor change behavior. (This file's other tests prove the assertable
    // half; `OTEL_SDK_DISABLED=1 pnpm test` proves the disabled posture.)
    await recording.restore();
    const marked = ConnectionMaterialSchema.parse(
      JSON.parse(await sealEnvelope({ access: "inert-access", refresh: "inert-refresh" })),
    );
    const row = await seedConnection({
      status: "invalidated",
      material: JSON.stringify(marked),
      pendingRetire: JSON.stringify(marked),
    });
    await sweep!.sweepOnce();
    expect(destroyed).toContain(marked.access);
    expect(destroyed).toContain(marked.refresh);
    expect(await readRow(row.id)).toMatchObject({ pendingRetire: null });
  });
});
