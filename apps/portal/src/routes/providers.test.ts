import { randomBytes, randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { DevEnvelopeSecretStore } from "@azx-pbc/secret-store";
import type { TokenVerifier } from "../plugins/auth.js";
import { connectionsCallbackUrl } from "../deployment.js";
import { authHeader, buildTestApp, type TestApp } from "../test/harness.js";

/**
 * Connection-provider CRUD: admin-direct, audited, metadata-only
 * reads, sealed credentials, the loaded-revision CAS on edit, and the fixed
 * callback hint derived from the apps base. The dev token carries the admin
 * group (PORTAL_DEV_ACTOR_GROUPS) for the main suite; the non-admin gate gets
 * its own app with an injected verifier chain, like routes/secrets.test.ts.
 */

let t: TestApp;
// A real envelope store under a throwaway key — proves seal/never-return without
// asserting the on-disk ciphertext (which the store owns).
const store = new DevEnvelopeSecretStore({ masterKey: randomBytes(32) });

beforeAll(async () => {
  t = buildTestApp({ secretStore: store });
  await t.app.ready();
});
afterAll(async () => {
  await t.close();
});

const CLIENT_ID = "vendor-client-id-xyz";
const CLIENT_SECRET = "vendor-client-secret-abc";

/** Every configured field on the create/edit form. */
const createBody = (ref: string, overrides: Record<string, unknown> = {}) => ({
  ref,
  kind: "rest-delegated",
  displayName: "Asana",
  env: "prod",
  authorizeEndpoint: "https://vendor.example/oauth/authorize",
  tokenEndpoint: "https://vendor.example/oauth/token",
  requestedScopes: ["default"],
  apiOrigins: ["https://vendor.example"],
  tokenPlacement: { kind: "header-bearer" },
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  ...overrides,
});

/** The full-replace edit body: every editable field plus the loaded revision. */
const editBody = (revision: number, overrides: Record<string, unknown> = {}) => ({
  displayName: "Asana Workflows",
  authorizeEndpoint: "https://vendor.example/oauth/authorize",
  tokenEndpoint: "https://vendor.example/oauth/token",
  requestedScopes: ["default"],
  apiOrigins: ["https://vendor.example"],
  tokenPlacement: { kind: "header-bearer" },
  revision,
  ...overrides,
});

async function post(payload: Record<string, unknown>) {
  return t.app.inject({ method: "POST", url: "/api/v1/providers", headers: authHeader(), payload });
}

async function createProvider(ref?: string, overrides: Record<string, unknown> = {}) {
  const res = await post(createBody(ref ?? randomProviderRef(), overrides));
  expect(res.statusCode).toBe(201);
  return res.json();
}

function randomProviderRef(): string {
  return `prov-${randomUUID().replace(/-/g, "").slice(0, 16)}`;
}

describe("provider create + inspect", () => {
  it("creates with the full field set and echoes metadata without any credential material", async () => {
    const ref = randomProviderRef();
    const created = await post(createBody(ref));
    expect(created.statusCode).toBe(201);
    const meta = created.json();
    expect(meta).toMatchObject({
      ref,
      kind: "rest-delegated",
      displayName: "Asana",
      env: "prod",
      authorizeEndpoint: "https://vendor.example/oauth/authorize",
      tokenEndpoint: "https://vendor.example/oauth/token",
      requestedScopes: ["default"],
      apiOrigins: ["https://vendor.example"],
      tokenPlacement: { kind: "header-bearer" },
      revision: 1,
    });
    // Credential material is absent from the payload shape — not empty, not
    // nulled: the fields do not exist on the metadata contract at all.
    expect(meta).not.toHaveProperty("clientId");
    expect(meta).not.toHaveProperty("clientSecret");
    expect(meta).not.toHaveProperty("clientIdMaterial");
    expect(meta).not.toHaveProperty("clientSecretMaterial");
    expect(created.payload).not.toContain(CLIENT_ID);
    expect(created.payload).not.toContain(CLIENT_SECRET);

    // …and the row carries sealed material, never plaintext.
    const row = await t.prisma.connectionProvider.findFirst({ where: { ref } });
    expect(row?.clientIdMaterial).toBeTruthy();
    expect(row?.clientSecretMaterial).toBeTruthy();
    expect(row?.clientIdMaterial).not.toContain(CLIENT_ID);
    expect(row?.clientSecretMaterial).not.toContain(CLIENT_SECRET);
  });

  it("returns every configured field on GET, still with no credential material", async () => {
    const meta = await createProvider();
    const got = await t.app.inject({
      method: "GET",
      url: `/api/v1/providers/${meta.id}`,
      headers: authHeader(),
    });
    expect(got.statusCode).toBe(200);
    const body = got.json();
    expect(body).toMatchObject({
      id: meta.id,
      ref: meta.ref,
      kind: "rest-delegated",
      displayName: "Asana",
      env: "prod",
      requestedScopes: ["default"],
      apiOrigins: ["https://vendor.example"],
      tokenPlacement: { kind: "header-bearer" },
      revision: 1,
    });
    expect(body).not.toHaveProperty("clientId");
    expect(body).not.toHaveProperty("clientSecret");
    expect(body).not.toHaveProperty("clientIdMaterial");
    expect(body).not.toHaveProperty("clientSecretMaterial");
    expect(got.payload).not.toContain(CLIENT_ID);
    expect(got.payload).not.toContain(CLIENT_SECRET);
  });

  it("answers 404 for an unknown provider id", async () => {
    const res = await t.app.inject({
      method: "GET",
      url: `/api/v1/providers/${randomUUID()}`,
      headers: authHeader(),
    });
    expect(res.statusCode).toBe(404);
  });

  it("rejects a malformed body with 422", async () => {
    // Uppercase refs fail ProviderRefSchema; a destination with a path fails
    // ApiOriginSchema — both are administrator typos to fix inline (422), not
    // server errors.
    expect((await post(createBody("Not-A-Ref"))).statusCode).toBe(422);
    expect(
      (await post(createBody(randomProviderRef(), { apiOrigins: ["https://v.example/api"] })))
        .statusCode,
    ).toBe(422);
  });
});

describe("duplicate creation conflicts per environment", () => {
  it("409s the same ref in the same env, naming the conflict; a different env succeeds", async () => {
    const ref = randomProviderRef();
    await createProvider(ref, { env: "prod" });
    const dup = await post(createBody(ref, { env: "prod" }));
    expect(dup.statusCode).toBe(409);
    expect(dup.json().error.message).toContain(ref);
    expect(dup.json().error.message).toContain("prod");

    // Env-unique ref: the same ref lands in the dev tier.
    const dev = await post(createBody(ref, { env: "dev" }));
    expect(dev.statusCode).toBe(201);
    expect(dev.json().env).toBe("dev");
  });
});

describe("editing with the revision CAS", () => {
  it("applies an edit carrying the loaded revision and reseeds the response", async () => {
    const meta = await createProvider();
    const put = await t.app.inject({
      method: "PUT",
      url: `/api/v1/providers/${meta.id}`,
      headers: authHeader(),
      payload: editBody(meta.revision),
    });
    expect(put.statusCode).toBe(200);
    expect(put.json()).toMatchObject({ id: meta.id, displayName: "Asana Workflows" });
  });

  it("rejects a stale revision with 409 and changes nothing", async () => {
    const meta = await createProvider();
    const before = await t.prisma.connectionProvider.findUnique({ where: { id: meta.id } });

    const stale = await t.app.inject({
      method: "PUT",
      url: `/api/v1/providers/${meta.id}`,
      headers: authHeader(),
      // A revision that was never current is stale the same way one from
      // before a peer's edit is (the compare-and-swap).
      payload: editBody(meta.revision + 7, { displayName: "Overwritten?" }),
    });
    expect(stale.statusCode).toBe(409);

    const after = await t.prisma.connectionProvider.findUnique({ where: { id: meta.id } });
    expect(after).toEqual(before);
  });

  it("answers 404 for an edit of an unknown provider", async () => {
    const res = await t.app.inject({
      method: "PUT",
      url: `/api/v1/providers/${randomUUID()}`,
      headers: authHeader(),
      payload: editBody(1),
    });
    expect(res.statusCode).toBe(404);
  });

  // Environment is immutable after create: there is no route to
  // move it, and the update body has no env field — the strict schema refuses
  // one rather than ignoring it, so a client that sends env learns the body is
  // wrong instead of silently not moving the row.
  it("refuses an update body that carries env", async () => {
    const meta = await createProvider();
    const res = await t.app.inject({
      method: "PUT",
      url: `/api/v1/providers/${meta.id}`,
      headers: authHeader(),
      payload: editBody(meta.revision, { env: "dev" }),
    });
    expect(res.statusCode).toBe(422);
  });
});

describe("client-secret rotation (blank-vs-supplied)", () => {
  it("keeps the existing secret when the credential fields are absent", async () => {
    const meta = await createProvider();
    const before = await t.prisma.connectionProvider.findUnique({ where: { id: meta.id } });

    const put = await t.app.inject({
      method: "PUT",
      url: `/api/v1/providers/${meta.id}`,
      headers: authHeader(),
      // No clientId / clientSecret keys — the edit form's "leave blank to keep".
      payload: editBody(meta.revision),
    });
    expect(put.statusCode).toBe(200);

    const after = await t.prisma.connectionProvider.findUnique({ where: { id: meta.id } });
    expect(after?.clientIdMaterial).toBe(before?.clientIdMaterial);
    expect(after?.clientSecretMaterial).toBe(before?.clientSecretMaterial);
    expect(after?.displayName).toBe("Asana Workflows");
  });

  it("seals a supplied secret and preserves the row apart from the sealed material", async () => {
    const meta = await createProvider();
    const before = await t.prisma.connectionProvider.findUnique({ where: { id: meta.id } });
    const NEW_SECRET = "brand-new-vendor-secret";

    const put = await t.app.inject({
      method: "PUT",
      url: `/api/v1/providers/${meta.id}`,
      headers: authHeader(),
      // displayName held constant — the full-replace body changes nothing but
      // the rotated half.
      payload: editBody(meta.revision, { displayName: "Asana", clientSecret: NEW_SECRET }),
    });
    expect(put.statusCode).toBe(200);

    const after = await t.prisma.connectionProvider.findUnique({ where: { id: meta.id } });
    // Row state unchanged apart from the rotated half: the identity material,
    // every configuration field, and the revision are exactly as they were.
    expect(after?.clientIdMaterial).toBe(before?.clientIdMaterial);
    expect(after?.clientSecretMaterial).not.toBe(before?.clientSecretMaterial);
    expect(after).toMatchObject({
      ref: before?.ref,
      kind: before?.kind,
      displayName: before?.displayName,
      env: before?.env,
      revision: before?.revision,
      authorizeEndpoint: before?.authorizeEndpoint,
      tokenEndpoint: before?.tokenEndpoint,
    });
    // The new secret is sealed, not stored plaintext.
    expect(after?.clientSecretMaterial).not.toContain(NEW_SECRET);
    // …and the response still carries no material.
    expect(put.payload).not.toContain(NEW_SECRET);
  });
});

describe("the fixed callback hint", () => {
  // The pin: the served value is exactly the reserved-subdomain derivation —
  // `auth.<APP_PUBLIC_BASE host>` + `/connections/callback`. If the derivation
  // drifts from the edge's
  // topology (hosts.ts classifies the `auth` label; connectionsProxy.ts
  // forwards the `/connections` prefix to this portal), administrators copy a
  // callback URL the vendor's redirects will never reach, so this fails loud.
  it("serves the reserved-subdomain derivation from APP_PUBLIC_BASE", async () => {
    vi.stubEnv("APP_PUBLIC_BASE", "https://apps.example.io");
    try {
      const list = await t.app.inject({
        method: "GET",
        url: "/api/v1/providers",
        headers: authHeader(),
      });
      expect(list.statusCode).toBe(200);
      expect(list.json().callbackUrl).toBe("https://auth.apps.example.io/connections/callback");
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("serves the control-domain auth host when CONTROL_PUBLIC_BASE is set", async () => {
    vi.stubEnv("APP_PUBLIC_BASE", "https://apps.example.com");
    vi.stubEnv("CONTROL_PUBLIC_BASE", "https://control.example.com");
    try {
      const list = await t.app.inject({
        method: "GET",
        url: "/api/v1/providers",
        headers: authHeader(),
      });
      expect(list.statusCode).toBe(200);
      expect(list.json().callbackUrl).toBe("https://auth.control.example.com/connections/callback");
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("carries a non-default port through the derivation", () => {
    expect(connectionsCallbackUrl({ APP_PUBLIC_BASE: "http://localhost:8081" })).toBe(
      "http://auth.localhost:8081/connections/callback",
    );
  });
});

describe("provider.created / provider.updated audit events", () => {
  it("records both, actor-stamped, with bounded metadata and no credential material", async () => {
    const ref = randomProviderRef();
    const meta = await createProvider(ref);
    await t.app.inject({
      method: "PUT",
      url: `/api/v1/providers/${meta.id}`,
      headers: authHeader(),
      payload: editBody(meta.revision, { clientSecret: "rotated-vendor-secret" }),
    });

    const events = await t.prisma.auditEvent.findMany({
      where: { action: { in: ["provider.created", "provider.updated"] } },
      orderBy: { createdAt: "asc" },
    });
    const mine = events.filter((e) => JSON.stringify(e.metadata).includes(ref));
    expect(mine.map((e) => e.action)).toEqual(["provider.created", "provider.updated"]);

    const created = mine[0];
    expect(created?.actor).toBeTruthy();
    expect(created?.metadata).toMatchObject({ ref, env: "prod", kind: "rest-delegated" });

    const updated = mine[1];
    expect(updated?.actor).toBeTruthy();
    expect(updated?.metadata).toMatchObject({
      ref,
      env: "prod",
      secretRotated: true,
      clientIdentityChanged: false,
    });
    // Bounded metadata: no credential, sealed material, or endpoint URL ever.
    for (const event of mine) {
      const serialized = JSON.stringify(event.metadata);
      expect(serialized).not.toContain(CLIENT_ID);
      expect(serialized).not.toContain(CLIENT_SECRET);
      expect(serialized).not.toContain("rotated-vendor-secret");
      expect(serialized).not.toContain("vendor.example");
    }
  });
});

/**
 * The gate + the CAS under genuine interleaving, against their own app with a
 * store that tracks live vault entries — the routes/secrets.test.ts style. The
 * admin gate is the first statement of each handler, ahead of any zod parse or
 * DB read, so a random id and an empty body still reach it.
 */
describe("provider routes refuse a non-admin", () => {
  const ADMIN_GROUP = "platform-admin";
  const verifiers: TokenVerifier[] = [
    {
      verify: async (token) => {
        if (token === "admin")
          return { oid: "oid-admin", sub: "admin@azx.io", via: "oidc", groups: [ADMIN_GROUP] };
        if (token === "plain")
          return { oid: "oid-plain", sub: "plain@azx.io", via: "oidc", groups: [] };
        return null;
      },
    },
  ];
  const admin = { authorization: "Bearer admin" };
  const plain = { authorization: "Bearer plain" };

  const ADMIN_ROUTES: [
    method: "GET" | "POST" | "PUT" | "DELETE",
    name: string,
    urlOf: (id: string) => string,
  ][] = [
    ["GET", "list", () => "/api/v1/providers"],
    ["POST", "create", () => "/api/v1/providers"],
    ["GET", "read", (id) => `/api/v1/providers/${id}`],
    ["PUT", "edit", (id) => `/api/v1/providers/${id}`],
    ["GET", "impact", (id) => `/api/v1/providers/${id}/impact`],
    ["DELETE", "delete", (id) => `/api/v1/providers/${id}`],
  ];

  let g: TestApp;

  beforeAll(async () => {
    vi.stubEnv("PORTAL_ADMIN_GROUP_ID", ADMIN_GROUP);
    g = buildTestApp({ secretStore: store, auth: { verifiers, publicConfig: null } });
    await g.app.ready();
  });

  afterAll(async () => {
    await g.close();
    vi.unstubAllEnvs();
  });

  it.each(ADMIN_ROUTES)("refuses %s (%s) for a signed-in non-admin", async (method, _n, urlOf) => {
    const res = await g.app.inject({ method, url: urlOf(randomUUID()), headers: plain });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe("forbidden");
  });

  it.each(ADMIN_ROUTES)("admits an admin to %s (%s)", async (method, _n, urlOf) => {
    // Positive control: the gate is not what stops these (they land on
    // 400/404/422 downstream — the ids don't exist).
    const res = await g.app.inject({ method, url: urlOf(randomUUID()), headers: admin });
    expect(res.statusCode).not.toBe(403);
  });

  it("leaves no row behind after a refused create", async () => {
    const ref = randomProviderRef();
    const refused = await g.app.inject({
      method: "POST",
      url: "/api/v1/providers",
      headers: plain,
      payload: createBody(ref),
    });
    expect(refused.statusCode).toBe(403);
    const rows = await g.prisma.connectionProvider.findMany({ where: { ref } });
    expect(rows).toEqual([]);
  });
});

/**
 * A dev store that also keeps a set of live "vault" entries, keyed by material,
 * plus a seal gate to force two edits to interleave — the only way both requests
 * can hold the same pre-edit state, which is the interleaving the CAS exists for.
 */
class TrackingStore extends DevEnvelopeSecretStore {
  readonly live = new Set<string>();
  readonly sealed = new Set<string>();
  stallNext: Promise<void> | null = null;
  onStall: (() => void) | null = null;
  override async seal(value: string): Promise<string> {
    const stall = this.stallNext;
    if (stall) {
      this.stallNext = null;
      this.onStall?.();
      this.onStall = null;
      await stall;
    }
    const material = await super.seal(value);
    this.live.add(material);
    this.sealed.add(material);
    return material;
  }
  override async destroy(material: string): Promise<void> {
    this.live.delete(material);
  }
}

describe("no path strands an unreferenced vault entry", () => {
  let t2: TestApp;
  let vault: TrackingStore;

  beforeAll(async () => {
    vault = new TrackingStore({ masterKey: randomBytes(32) });
    t2 = buildTestApp({ secretStore: vault });
    await t2.app.ready();
  });
  afterAll(async () => {
    await t2.close();
  });

  const inject = (method: "POST" | "PUT", url: string, payload?: Record<string, unknown>) =>
    t2.app.inject({ method, url, headers: authHeader(), payload });

  /** Materials the DB references, scoped to what *this* store minted. */
  async function referenced(): Promise<Set<string>> {
    const rows = await t2.prisma.connectionProvider.findMany({
      select: { clientIdMaterial: true, clientSecretMaterial: true },
    });
    return new Set(
      rows
        .flatMap((r) => [r.clientIdMaterial, r.clientSecretMaterial])
        .filter((m) => vault.sealed.has(m)),
    );
  }

  async function expectNoOrphans(): Promise<void> {
    const refs = await referenced();
    expect([...vault.live].filter((m) => !refs.has(m))).toEqual([]);
  }

  it("releases both materials when a create loses the ref+env uniqueness race", async () => {
    const ref = randomProviderRef();
    expect((await inject("POST", "/api/v1/providers", createBody(ref))).statusCode).toBe(201);
    const dup = await inject("POST", "/api/v1/providers", createBody(ref));
    expect(dup.statusCode).toBe(409);
    await expectNoOrphans();
  });

  it("exactly one of two concurrent rotations wins; the loser releases its material", async () => {
    const created = await inject("POST", "/api/v1/providers", createBody(randomProviderRef()));
    expect(created.statusCode).toBe(201);
    const meta = created.json();

    // Stall A's seal so B runs to completion in between. Both requests then
    // hold the same pre-edit row — the state a plain update would resolve as
    // last-write-wins, leaving the loser's sealed material live and stranded.
    let release!: () => void;
    let entered!: () => void;
    const stalled = new Promise<void>((r) => {
      entered = r;
    });
    vault.stallNext = new Promise<void>((r) => {
      release = r;
    });
    vault.onStall = entered;

    // The async IIFE matters: light-weight inject defers dispatch until .then().
    const a = (async () =>
      inject("PUT", `/api/v1/providers/${meta.id}`, {
        ...editBody(meta.revision, { displayName: "Edit A" }),
        clientSecret: "a-new-secret",
      }))();
    await stalled; // A has read the row and is parked inside seal()
    const b = await inject("PUT", `/api/v1/providers/${meta.id}`, {
      ...editBody(meta.revision, { displayName: "Edit B" }),
      clientSecret: "b-new-secret",
    });
    release();

    expect(b.statusCode).toBe(200); // B read and wrote while A was stalled
    expect((await a).statusCode).toBe(409); // A's compare-and-swap finds the row moved

    const row = await t2.prisma.connectionProvider.findUnique({ where: { id: meta.id } });
    expect(row?.displayName).toBe("Edit B"); // exactly one winner
    expect(row?.clientSecretMaterial).not.toContain("b-new-secret");
    await expectNoOrphans(); // …and A released the material it had already sealed
  });

  it("leaves no orphan and no dead reference across the whole suite", async () => {
    const refs = await referenced();
    expect([...vault.live].filter((m) => !refs.has(m))).toEqual([]);
    expect([...refs].filter((m) => !vault.live.has(m))).toEqual([]);
  });
});
