import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PrismaClient } from "../db/client.js";
import {
  authHeader,
  buildTestApp,
  createTestPrisma,
  uniqueSlug,
  type TestApp,
} from "../test/harness.js";

let t: TestApp;

beforeAll(async () => {
  t = buildTestApp();
  await t.app.ready();
});

afterAll(async () => {
  await t.close();
});

function createApp(payload: Record<string, unknown>) {
  return t.app.inject({ method: "POST", url: "/api/v1/apps", headers: authHeader(), payload });
}

function createdApp(res: { json: () => unknown }) {
  return res.json() as { id: string };
}

describe("POST /api/v1/apps", () => {
  it("creates an app (201), defaulting visibility to internal", async () => {
    const slug = uniqueSlug();
    const res = await createApp({ slug, displayName: "My App" });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.slug).toBe(slug);
    expect(body.displayName).toBe("My App");
    expect(body.visibility).toEqual({ mode: "internal" });
    expect(body.currentVersionId).toBeNull();
    expect(body.pending).toBeNull();
    expect(body.applied).toEqual([]);
  });

  it("rejects an unauthenticated request (401)", async () => {
    const res = await t.app.inject({
      method: "POST",
      url: "/api/v1/apps",
      payload: { slug: uniqueSlug(), displayName: "X" },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().error.code).toBe("unauthorized");
  });

  it("rejects a duplicate slug (409 slug_taken)", async () => {
    const slug = uniqueSlug();
    expect((await createApp({ slug, displayName: "First" })).statusCode).toBe(201);
    const res = await createApp({ slug, displayName: "Second" });
    expect(res.statusCode).toBe(409);
    expect(res.json().error.code).toBe("slug_taken");
  });

  it("rejects a non-DNS-label slug (400 validation_failed)", async () => {
    const res = await createApp({ slug: "Bad Slug", displayName: "X" });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("validation_failed");
  });

  it("creates with an optional description and round-trips it on read", async () => {
    const slug = uniqueSlug();
    const created = await createApp({
      slug,
      displayName: "Described",
      description: "Tracks Q3 spend by team.",
    });
    expect(created.statusCode).toBe(201);
    expect(created.json().description).toBe("Tracks Q3 spend by team.");

    const got = await t.app.inject({
      method: "GET",
      url: `/api/v1/apps/${slug}`,
      headers: authHeader(),
    });
    expect(got.json().description).toBe("Tracks Q3 spend by team.");
  });

  it("omits the description key entirely when unset", async () => {
    const slug = uniqueSlug();
    const created = await createApp({ slug, displayName: "Undescribed" });
    expect(created.statusCode).toBe(201);
    expect("description" in created.json()).toBe(false);
  });

  it("rejects an over-length description (400 validation_failed)", async () => {
    const res = await createApp({
      slug: uniqueSlug(),
      displayName: "X",
      description: "a".repeat(501),
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("validation_failed");
  });

  it("write-gate: baseline capabilities at create commit on the row", async () => {
    const slug = uniqueSlug();
    const res = await createApp({
      slug,
      displayName: "Baseline create",
      capabilities: { llm: { models: ["claude-opus-4-8"], dollarsPerDay: 25 } },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.pending).toBeNull();
    expect(body.applied.length).toBeGreaterThan(0);

    const got = await t.app.inject({
      method: "GET",
      url: `/api/v1/apps/${slug}/manifest`,
      headers: authHeader(),
    });
    expect(got.json().capabilities.llm).toEqual({
      models: ["claude-opus-4-8"],
      dollarsPerDay: 25,
    });
  });

  it("write-gate: elevated LLM budget at create stores baseline only and opens a request", async () => {
    const slug = uniqueSlug();
    const res = await createApp({
      slug,
      displayName: "High budget",
      capabilities: { llm: { models: ["claude-opus-4-8"], dollarsPerDay: 100 } },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(typeof body.pending).toBe("string");
    expect(body.applied.map((d: { path: string }) => d.path)).toContain(
      "llm.models[+claude-opus-4-8]",
    );

    const got = await t.app.inject({
      method: "GET",
      url: `/api/v1/apps/${slug}/manifest`,
      headers: authHeader(),
    });
    expect(got.json().capabilities.llm).toEqual({ models: ["claude-opus-4-8"] });

    const reqs = await t.prisma.approvalRequest.findMany({
      where: { appId: body.id },
    });
    expect(reqs).toHaveLength(1);
    expect(reqs[0]?.status).toBe("pending");
    expect(reqs[0]?.deltas).toEqual(
      expect.arrayContaining([expect.objectContaining({ path: "llm.dollarsPerDay" })]),
    );
  });

  it("write-gate: a fresh LLM grant with no budget at create opens a pending request", async () => {
    const slug = uniqueSlug();
    const res = await createApp({
      slug,
      displayName: "Unset cap",
      capabilities: { llm: { models: ["claude-opus-4-8"] } },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(typeof body.pending).toBe("string");

    const got = await t.app.inject({
      method: "GET",
      url: `/api/v1/apps/${slug}/manifest`,
      headers: authHeader(),
    });
    expect(got.json().capabilities.llm).toEqual({ models: ["claude-opus-4-8"] });

    const reqs = await t.prisma.approvalRequest.findMany({
      where: { appId: body.id },
    });
    expect(reqs).toHaveLength(1);
    expect(reqs[0]?.deltas).toEqual(
      expect.arrayContaining([expect.objectContaining({ path: "llm.dollarsPerDay" })]),
    );
  });
});

describe("PATCH /api/v1/apps/:slug", () => {
  it("sets, edits and clears the description, auditing each real change", async () => {
    const slug = uniqueSlug();
    await createApp({ slug, displayName: "Editable" });

    const set = await t.app.inject({
      method: "PATCH",
      url: `/api/v1/apps/${slug}`,
      headers: authHeader(),
      payload: { description: "First summary." },
    });
    expect(set.statusCode).toBe(200);
    expect(set.json().description).toBe("First summary.");

    const edited = await t.app.inject({
      method: "PATCH",
      url: `/api/v1/apps/${slug}`,
      headers: authHeader(),
      payload: { description: "Second summary." },
    });
    expect(edited.json().description).toBe("Second summary.");

    const cleared = await t.app.inject({
      method: "PATCH",
      url: `/api/v1/apps/${slug}`,
      headers: authHeader(),
      payload: { description: null },
    });
    expect(cleared.statusCode).toBe(200);
    // Cleared means omitted on the wire, same as never set.
    expect("description" in cleared.json()).toBe(false);
  });

  it("treats an absent key as no change and a no-op value as no write", async () => {
    const slug = uniqueSlug();
    const created = await createApp({
      slug,
      displayName: "Stable",
      description: "Unchanged.",
    });
    const updatedAt = created.json().updatedAt;

    const empty = await t.app.inject({
      method: "PATCH",
      url: `/api/v1/apps/${slug}`,
      headers: authHeader(),
      payload: {},
    });
    expect(empty.statusCode).toBe(200);
    expect(empty.json().description).toBe("Unchanged.");

    const same = await t.app.inject({
      method: "PATCH",
      url: `/api/v1/apps/${slug}`,
      headers: authHeader(),
      payload: { description: "Unchanged." },
    });
    expect(same.statusCode).toBe(200);
    // A no-op must not bump `updatedAt` — the record did not change.
    expect(same.json().updatedAt).toBe(updatedAt);
  });

  it("rejects an over-length description (400 validation_failed)", async () => {
    const slug = uniqueSlug();
    await createApp({ slug, displayName: "Capped" });
    const res = await t.app.inject({
      method: "PATCH",
      url: `/api/v1/apps/${slug}`,
      headers: authHeader(),
      payload: { description: "a".repeat(501) },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("validation_failed");
  });

  it("404s an unknown slug", async () => {
    const res = await t.app.inject({
      method: "PATCH",
      url: `/api/v1/apps/${uniqueSlug()}`,
      headers: authHeader(),
      payload: { description: "x" },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe("not_found");
  });

  it("records the changed description in the app.update audit trail", async () => {
    const slug = uniqueSlug();
    const created = await createApp({ slug, displayName: "Audited" });
    const appId = createdApp(created).id;
    await t.app.inject({
      method: "PATCH",
      url: `/api/v1/apps/${slug}`,
      headers: authHeader(),
      payload: { description: "Recorded." },
    });
    const events = await t.prisma.auditEvent.findMany({
      where: { appId, action: "app.update" },
    });
    expect(events).toHaveLength(1);
    expect(events[0]?.metadata).toEqual({ description: "Recorded." });
  });
});

describe("POST /api/v1/apps/:slug/archive and /unarchive", () => {
  it("archives and unarchives an app, idempotently, with audit events", async () => {
    const slug = uniqueSlug();
    const created = await createApp({ slug, displayName: "Archivable" });
    expect(created.json().archivedAt).toBeNull();

    const archived = await t.app.inject({
      method: "POST",
      url: `/api/v1/apps/${slug}/archive`,
      headers: authHeader(),
    });
    expect(archived.statusCode).toBe(200);
    expect(archived.json().archivedAt).not.toBeNull();

    // Idempotent: re-archiving keeps the original timestamp.
    const again = await t.app.inject({
      method: "POST",
      url: `/api/v1/apps/${slug}/archive`,
      headers: authHeader(),
    });
    expect(again.statusCode).toBe(200);
    expect(again.json().archivedAt).toBe(archived.json().archivedAt);

    const unarchived = await t.app.inject({
      method: "POST",
      url: `/api/v1/apps/${slug}/unarchive`,
      headers: authHeader(),
    });
    expect(unarchived.statusCode).toBe(200);
    expect(unarchived.json().archivedAt).toBeNull();

    const appId = createdApp(created).id;
    const events = await t.prisma.auditEvent.findMany({ where: { appId } });
    const actions = events.map((e) => e.action);
    expect(actions).toContain("app.archive");
    expect(actions).toContain("app.unarchive");
    // Idempotent re-archive must not have produced a second archive event.
    expect(actions.filter((a) => a === "app.archive")).toHaveLength(1);
  });

  it("requires auth (401) and 404s on unknown slug", async () => {
    const noAuth = await t.app.inject({
      method: "POST",
      url: `/api/v1/apps/${uniqueSlug()}/archive`,
    });
    expect(noAuth.statusCode).toBe(401);

    const missing = await t.app.inject({
      method: "POST",
      url: `/api/v1/apps/${uniqueSlug()}/archive`,
      headers: authHeader(),
    });
    expect(missing.statusCode).toBe(404);
  });
});

describe("manifest (capabilities) GET/PUT", () => {
  it("stores capabilities at create time and returns them via the manifest", async () => {
    const slug = uniqueSlug();
    await createApp({
      slug,
      displayName: "LLM App",
      capabilities: { llm: { models: ["claude-opus-4-8"], dollarsPerDay: 10 } },
    });

    const got = await t.app.inject({
      method: "GET",
      url: `/api/v1/apps/${slug}/manifest`,
      headers: authHeader(),
    });
    expect(got.statusCode).toBe(200);
    expect(got.json()).toEqual({
      app: slug,
      visibility: { mode: "internal" },
      capabilities: {
        llm: { models: ["claude-opus-4-8"], dollarsPerDay: 10 },
        mcp: [],
        externalOrigins: [],
      },
    });
  });

  it("defaults to the baseline grant set when capabilities are omitted", async () => {
    const slug = uniqueSlug();
    await createApp({ slug, displayName: "Bare" });
    const got = await t.app.inject({
      method: "GET",
      url: `/api/v1/apps/${slug}/manifest`,
      headers: authHeader(),
    });
    expect(got.json().capabilities).toEqual({ mcp: [], externalOrigins: [] });
  });

  it("replaces grants via PUT (auth required) and audits the change", async () => {
    const slug = uniqueSlug();
    const created = await createApp({ slug, displayName: "Editable" });

    const noAuth = await t.app.inject({
      method: "PUT",
      url: `/api/v1/apps/${slug}/manifest`,
      payload: { capabilities: { llm: { models: ["m"] } } },
    });
    expect(noAuth.statusCode).toBe(401);

    const put = await t.app.inject({
      method: "PUT",
      url: `/api/v1/apps/${slug}/manifest`,
      headers: authHeader(),
      payload: { capabilities: { llm: { models: ["claude-opus-4-8"], dollarsPerDay: 25 } } },
    });
    expect(put.statusCode).toBe(200);
    // Curated model + sub-baseline budget → all baseline, nothing pending.
    expect(put.json().manifest.capabilities.llm).toEqual({
      models: ["claude-opus-4-8"],
      dollarsPerDay: 25,
    });
    expect(put.json().pending).toBeNull();

    const events = await t.prisma.auditEvent.findMany({ where: { appId: createdApp(created).id } });
    expect(events.map((e) => e.action)).toContain("app.manifest.set");
  });

  it("write-gate: commits baseline deltas live but bundles elevated ones into a pending request", async () => {
    const slug = uniqueSlug();
    const created = await createApp({ slug, displayName: "Gated" });

    const put = await t.app.inject({
      method: "PUT",
      url: `/api/v1/apps/${slug}/manifest`,
      headers: authHeader(),
      payload: {
        capabilities: {
          // baseline: a data scope grant
          data: { user: true },
          // elevated: an arbitrary MCP server (high risk)
          mcp: ["pagerduty"],
        },
      },
    });
    expect(put.statusCode).toBe(200);
    const body = put.json();
    // The pending part is NOT applied to the live manifest.
    expect(body.manifest.capabilities.mcp).toEqual([]);
    expect(body.manifest.capabilities.data.user).toBe(true);
    expect(typeof body.pending).toBe("string");

    const reqs = await t.prisma.approvalRequest.findMany({
      where: { appId: createdApp(created).id },
    });
    expect(reqs).toHaveLength(1);
    expect(reqs[0]?.status).toBe("pending");
    expect(reqs[0]?.risk).toBe("high");

    const events = await t.prisma.auditEvent.findMany({ where: { appId: createdApp(created).id } });
    expect(events.map((e) => e.action)).toEqual(
      expect.arrayContaining(["app.manifest.set", "approval.request"]),
    );
  });

  it("404s setting a manifest on an unknown slug", async () => {
    const res = await t.app.inject({
      method: "PUT",
      url: `/api/v1/apps/${uniqueSlug()}/manifest`,
      headers: authHeader(),
      payload: { capabilities: { llm: { models: ["m"] } } },
    });
    expect(res.statusCode).toBe(404);
  });
});

describe("GET /api/v1/apps and /:slug", () => {
  it("round-trips a group-visibility app and 404s on unknown", async () => {
    const slug = uniqueSlug();
    await createApp({
      slug,
      displayName: "Grouped",
      visibility: { mode: "group", groupIds: ["g1"] },
    });

    const got = await t.app.inject({
      method: "GET",
      url: `/api/v1/apps/${slug}`,
      headers: authHeader(),
    });
    expect(got.statusCode).toBe(200);
    expect(got.json().visibility).toEqual({ mode: "group", groupIds: ["g1"] });

    const list = await t.app.inject({
      method: "GET",
      url: "/api/v1/apps",
      headers: authHeader(),
    });
    expect(list.statusCode).toBe(200);
    expect(list.json().some((a: { slug: string }) => a.slug === slug)).toBe(true);

    const missing = await t.app.inject({
      method: "GET",
      url: `/api/v1/apps/${uniqueSlug()}`,
      headers: authHeader(),
    });
    expect(missing.statusCode).toBe(404);
    expect(missing.json().error.code).toBe("not_found");
  });

  // Clients render this rather than templating `<slug>.<domain>` themselves —
  // the SPA ships prebuilt, so anything it composed would be wrong per-deploy.
  it("carries the app's public URL, composed from the deployment's apps base", async () => {
    const slug = uniqueSlug();
    const created = await createApp({ slug, displayName: "Locatable" });
    expect(created.json().url).toBe(`https://${slug}.local.helix.azxlabs.io:8080`);

    const detail = await t.app.inject({
      method: "GET",
      url: `/api/v1/apps/${slug}`,
      headers: authHeader(),
    });
    expect(detail.json().url).toBe(`https://${slug}.local.helix.azxlabs.io:8080`);

    const list = await t.app.inject({ method: "GET", url: "/api/v1/apps", headers: authHeader() });
    const listed = list.json().find((a: { slug: string }) => a.slug === slug);
    expect(listed.url).toBe(`https://${slug}.local.helix.azxlabs.io:8080`);
  });

  it("follows APP_PUBLIC_BASE, so a redeploy to a new domain needs no client change", async () => {
    const prev = process.env.APP_PUBLIC_BASE;
    process.env.APP_PUBLIC_BASE = "https://apps.example.com";
    try {
      const slug = uniqueSlug();
      const created = await createApp({ slug, displayName: "Rehomed" });
      expect(created.json().url).toBe(`https://${slug}.apps.example.com`);
    } finally {
      if (prev === undefined) delete process.env.APP_PUBLIC_BASE;
      else process.env.APP_PUBLIC_BASE = prev;
    }
  });

  it("keeps app URLs on the apps host when CONTROL_PUBLIC_BASE is set", async () => {
    const prevBase = process.env.APP_PUBLIC_BASE;
    const prevControl = process.env.CONTROL_PUBLIC_BASE;
    process.env.APP_PUBLIC_BASE = "https://apps.example.com";
    process.env.CONTROL_PUBLIC_BASE = "https://control.example.com";
    try {
      const slug = uniqueSlug();
      const created = await createApp({ slug, displayName: "Split" });
      expect(created.json().url).toBe(`https://${slug}.apps.example.com`);
      expect(created.json().url).not.toContain("control.example.com");
    } finally {
      if (prevBase === undefined) delete process.env.APP_PUBLIC_BASE;
      else process.env.APP_PUBLIC_BASE = prevBase;
      if (prevControl === undefined) delete process.env.CONTROL_PUBLIC_BASE;
      else process.env.CONTROL_PUBLIC_BASE = prevControl;
    }
  });

  it("requires sign-in to read the registry (401)", async () => {
    const list = await t.app.inject({ method: "GET", url: "/api/v1/apps" });
    expect(list.statusCode).toBe(401);
    expect(list.json().error.code).toBe("unauthorized");

    const slug = uniqueSlug();
    await createApp({ slug, displayName: "Hidden" });
    const detail = await t.app.inject({ method: "GET", url: `/api/v1/apps/${slug}` });
    expect(detail.statusCode).toBe(401);
    const manifest = await t.app.inject({ method: "GET", url: `/api/v1/apps/${slug}/manifest` });
    expect(manifest.statusCode).toBe(401);
  });
});

describe("operator policy: PORTAL_ALLOW_PUBLIC_APPS=false", () => {
  const setVisibility = (slug: string, body: Record<string, unknown>) =>
    t.app.inject({
      method: "POST",
      url: `/api/v1/apps/${slug}/visibility`,
      headers: authHeader(),
      payload: body,
    });

  async function withPublicDisallowed(fn: () => Promise<void>): Promise<void> {
    const prev = process.env.PORTAL_ALLOW_PUBLIC_APPS;
    process.env.PORTAL_ALLOW_PUBLIC_APPS = "false";
    try {
      await fn();
    } finally {
      if (prev === undefined) delete process.env.PORTAL_ALLOW_PUBLIC_APPS;
      else process.env.PORTAL_ALLOW_PUBLIC_APPS = prev;
    }
  }

  it("refuses to create a public app (403 forbidden)", async () => {
    await withPublicDisallowed(async () => {
      const res = await createApp({
        slug: uniqueSlug(),
        displayName: "Would-be public",
        visibility: { mode: "public" },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe("forbidden");
    });
  });

  it("refuses the elevated → public change instead of opening an approval (403)", async () => {
    const slug = uniqueSlug();
    await createApp({ slug, displayName: "Private now" });
    await withPublicDisallowed(async () => {
      const res = await setVisibility(slug, { visibility: { mode: "public" } });
      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe("forbidden");
    });
    // No approval request was opened.
    const reqs = await t.prisma.approvalRequest.findMany({
      where: { app: { slug } },
    });
    expect(reqs).toHaveLength(0);
  });

  it("still allows reductions (→ group) so an app can move off an open surface", async () => {
    const slug = uniqueSlug();
    await createApp({ slug, displayName: "Reducible" });
    await withPublicDisallowed(async () => {
      const res = await setVisibility(slug, { visibility: { mode: "group", groupIds: ["g1"] } });
      expect(res.statusCode).toBe(200);
      expect(res.json().applied).toHaveLength(1);
    });
  });

  /**
   * The route-level half of ADR-0040 §5's regression. `classifyVisibilityChange`
   * used to compare bare modes, so `group → group` returned null and the handler
   * treats null as a no-op and returns before writing — editing which group could
   * open an app answered **200 with no write and no audit row**. That was
   * invisible while an app held one group behind a free-text box; it is the
   * central operation now, so it gets asserted at the route, not only in the
   * classifier's unit test.
   */
  it("applies a group-set edit that leaves the mode alone, and audits it", async () => {
    const slug = uniqueSlug();
    await createApp({
      slug,
      displayName: "Regrouped",
      visibility: { mode: "group", groupIds: ["eng"] },
    });

    const res = await setVisibility(slug, {
      visibility: { mode: "group", groupIds: ["eng", "product"] },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().pending).toBeNull(); // baseline — applies immediately
    expect(res.json().applied).toEqual([
      { path: "visibility", from: "group:eng", to: "group:eng,product", risk: "low" },
    ]);
    expect(res.json().app.visibility).toEqual({ mode: "group", groupIds: ["eng", "product"] });

    // The write actually landed, rather than the response merely describing it.
    const row = await t.prisma.app.findUniqueOrThrow({ where: { slug } });
    expect(row.visibilityGroupIds).toEqual(["eng", "product"]);

    // And the audit row carries the machine-readable set, not just the diff —
    // an audit entry is the only place group values are recorded at all (§7).
    const events = await t.prisma.auditEvent.findMany({
      where: { appId: row.id, action: "app.visibility.set" },
    });
    expect(events).toHaveLength(1);
    expect(events[0]?.metadata).toMatchObject({ groupIds: ["eng", "product"] });
    // Names come from the directory at write time (ADR-0040 §7 — the audit row is
    // the one place a name is recorded, because it is a historical fact rather
    // than a cache). The default test harness has no directory that knows "eng",
    // so the key is absent rather than null — "we could not name these", not
    // "these have no names". The named case is covered in directory.test.ts.
    expect(events[0]?.metadata).not.toHaveProperty("groupNames");
  });

  it("removing a group is also a baseline write, not a no-op", async () => {
    const slug = uniqueSlug();
    await createApp({
      slug,
      displayName: "Narrowed",
      visibility: { mode: "group", groupIds: ["eng", "product"] },
    });
    const res = await setVisibility(slug, { visibility: { mode: "group", groupIds: ["eng"] } });
    expect(res.statusCode).toBe(200);
    expect(res.json().applied).toHaveLength(1);
    const row = await t.prisma.app.findUniqueOrThrow({ where: { slug } });
    expect(row.visibilityGroupIds).toEqual(["eng"]);
  });

  // Order is meaningless in an any-of set, so re-sending the same groups in a
  // different order must stay a genuine no-op: no write, no policyVersion bump
  // (which forces an edge projection reload), no audit row.
  it("treats a reordered group set as a no-op", async () => {
    const slug = uniqueSlug();
    await createApp({
      slug,
      displayName: "Reordered",
      visibility: { mode: "group", groupIds: ["eng", "product"] },
    });
    const before = await t.prisma.app.findUniqueOrThrow({ where: { slug } });
    const res = await setVisibility(slug, {
      visibility: { mode: "group", groupIds: ["product", "eng"] },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().applied).toEqual([]);
    const after = await t.prisma.app.findUniqueOrThrow({ where: { slug } });
    expect(after.policyVersion).toBe(before.policyVersion);
    const events = await t.prisma.auditEvent.findMany({
      where: { appId: before.id, action: "app.visibility.set" },
    });
    expect(events).toHaveLength(0);
  });

  /**
   * The label-as-equality-key collision, at the route. `["eng","prod"]` and
   * `["eng,prod"]` render the same `group:eng,prod`, so switching between them
   * compared equal and the handler took its no-op branch: 200, no write, no audit.
   * The reverse mattered more — an app scoped to the single id (which admits
   * nobody) could not be corrected.
   *
   * The write path now refuses the comma outright, which is the belt; the classifier
   * comparing sets is the braces, and `approval.test.ts` pins that directly.
   */
  it("refuses a group id containing the label delimiter (400)", async () => {
    const slug = uniqueSlug();
    await createApp({ slug, displayName: "Pasted" });
    for (const bad of ["eng,prod", "eng prod"]) {
      const res = await setVisibility(slug, { visibility: { mode: "group", groupIds: [bad] } });
      expect(res.statusCode).toBe(400);
      expect(res.json().error.code).toBe("validation_failed");
    }
  });

  it("dedupes a repeated group id rather than storing or counting it twice", async () => {
    const slug = uniqueSlug();
    await createApp({ slug, displayName: "Duped" });
    const res = await setVisibility(slug, {
      visibility: { mode: "group", groupIds: ["eng", "eng", "prod"] },
    });
    expect(res.statusCode).toBe(200);
    const row = await t.prisma.app.findUniqueOrThrow({ where: { slug } });
    expect(row.visibilityGroupIds).toEqual(["eng", "prod"]);
    // And the delta reads as the set, not as `group:eng,eng,prod`.
    expect(res.json().applied).toEqual([
      { path: "visibility", from: "internal", to: "group:eng,prod", risk: "low" },
    ]);
  });

  it("refuses more than the capped number of groups (400)", async () => {
    const slug = uniqueSlug();
    await createApp({ slug, displayName: "Too many" });
    const res = await setVisibility(slug, {
      visibility: {
        mode: "group",
        groupIds: Array.from({ length: 11 }, (_, i) => `g${i}`),
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("validation_failed");
  });
});

/**
 * Concurrent writes to an app's effective policy state (docs/design/approvals.md
 * §5). `capabilities` is replaced whole, so without the `policyVersion` CAS two
 * writers computing from the same pre-image silently discard each other's deltas
 * and both are told 200.
 */
describe("concurrent policy writes", () => {
  /** A client whose `apps` CAS write is parked until released. */
  function gatedPolicyWrite() {
    let reachedItsWrite!: () => void;
    const atTheWrite = new Promise<void>((resolve) => {
      reachedItsWrite = resolve;
    });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const prisma = createTestPrisma().$extends({
      query: {
        app: {
          async updateMany({ args, query }) {
            reachedItsWrite();
            await gate;
            return query(args);
          },
        },
      },
    }) as unknown as PrismaClient;
    return { prisma, atTheWrite, release };
  }

  it("409s the manifest PUT that lost, instead of discarding the other's deltas", async () => {
    const slug = uniqueSlug();
    await createApp({ slug, displayName: "Contended" });
    const gated = gatedPolicyWrite();
    const slow = buildTestApp({ prisma: gated.prisma });
    await slow.app.ready();
    try {
      // The async IIFE matters: light-my-request defers dispatch until something
      // awaits the chain, so a bare `inject()` never runs (secrets.test.ts:395).
      const first = (async () =>
        slow.app.inject({
          method: "PUT",
          url: `/api/v1/apps/${slug}/manifest`,
          headers: authHeader(),
          payload: { capabilities: { data: { user: true } } },
        }))();
      // It has read the pre-image and is about to write it back. Let a second,
      // unrelated baseline change commit underneath it first.
      await gated.atTheWrite;
      const second = await t.app.inject({
        method: "PUT",
        url: `/api/v1/apps/${slug}/manifest`,
        headers: authHeader(),
        payload: { capabilities: { llm: { models: ["claude-opus-4-8"], dollarsPerDay: 10 } } },
      });
      expect(second.statusCode).toBe(200);
      gated.release();
      const lost = await first;

      expect(lost.statusCode).toBe(409);
      expect(lost.json().error.code).toBe("conflict");

      // The committed change survived intact — the loser wrote nothing.
      const manifest = await t.app.inject({
        method: "GET",
        url: `/api/v1/apps/${slug}/manifest`,
        headers: authHeader(),
      });
      expect(manifest.json().capabilities.llm).toEqual({
        models: ["claude-opus-4-8"],
        dollarsPerDay: 10,
      });
      expect(manifest.json().capabilities.data?.user ?? false).toBe(false);
    } finally {
      await slow.close();
    }
  });

  it("hands the losing password-enable a 409 rather than a passphrase that is not stored", async () => {
    const slug = uniqueSlug();
    await createApp({ slug, displayName: "Passworded" });
    const gated = gatedPolicyWrite();
    const slow = buildTestApp({ prisma: gated.prisma });
    await slow.app.ready();
    try {
      const first = (async () =>
        slow.app.inject({
          method: "POST",
          url: `/api/v1/apps/${slug}/access/password`,
          headers: authHeader(),
        }))();
      await gated.atTheWrite;
      const second = await t.app.inject({
        method: "POST",
        url: `/api/v1/apps/${slug}/access/password`,
        headers: authHeader(),
      });
      expect(second.statusCode).toBe(201);
      gated.release();
      const lost = await first;

      // The whole point: 201 + a cleartext passphrase that does not open the app
      // is unrecoverable — the caller cannot tell it is the wrong one.
      expect(lost.statusCode).toBe(409);
      const stored = await t.app.inject({
        method: "GET",
        url: `/api/v1/apps/${slug}/access/password`,
        headers: authHeader(),
      });
      expect(stored.json().password).toBe(second.json().password);
    } finally {
      await slow.close();
    }
  });

  it("files both origin grants concurrently — an elevated-only change writes nothing to CAS over", async () => {
    const slug = uniqueSlug();
    const created = await createApp({ slug, displayName: "Origins" });
    const grant = (origin: string) =>
      t.app.inject({
        method: "POST",
        url: `/api/v1/apps/${slug}/access/origin`,
        headers: authHeader(),
        payload: { origin },
      });
    const [a, b] = await Promise.all([grant("https://one.example"), grant("https://two.example")]);
    // Neither grant changes the live blob (the origin waits for approval), so
    // neither may be turned away as a conflict and no origin may be dropped.
    expect([a.statusCode, b.statusCode]).toEqual([200, 200]);
    const reqs = await t.prisma.approvalRequest.findMany({
      where: { appId: createdApp(created).id },
    });
    expect(reqs).toHaveLength(2);
    expect(reqs.flatMap((r) => (r.deltas as { path: string }[]).map((d) => d.path)).sort()).toEqual(
      ["externalOrigins[+https://one.example]", "externalOrigins[+https://two.example]"],
    );
  });
});
