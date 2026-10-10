import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { TokenVerifier } from "../plugins/auth.js";
import { buildTestApp, uniqueSlug, type TestApp } from "../test/harness.js";

const ADMIN_GROUP = "platform-admin";
const verifiers: TokenVerifier[] = [
  {
    verify: async (t) => {
      if (t === "owner") return { oid: "oid-owner", sub: "owner@azx.io", via: "oidc", groups: [] };
      if (t === "admin")
        return { oid: "oid-admin", sub: "admin@azx.io", via: "oidc", groups: [ADMIN_GROUP] };
      return null;
    },
  },
];
const owner = { authorization: "Bearer owner" };
const admin = { authorization: "Bearer admin" };

let t: TestApp;

beforeAll(async () => {
  process.env.PORTAL_ADMIN_GROUP_ID = ADMIN_GROUP;
  t = buildTestApp({ auth: { verifiers, publicConfig: null } });
  await t.app.ready();
});

afterAll(async () => {
  await t.close();
});

describe("GET /api/v1/csp/violations", () => {
  it("aggregates reported violations for admins and refuses non-admins", async () => {
    const slug = uniqueSlug();
    const created = await t.app.inject({
      method: "POST",
      url: "/api/v1/apps",
      headers: owner,
      payload: { slug, displayName: "v" },
    });
    const appId = created.json().id as string;

    // Seed two reports for the same blocked origin (simulating the edge sink).
    for (let i = 0; i < 2; i++) {
      await t.prisma.cspReport.create({
        data: { appId, directive: "connect-src", blockedUri: "https://api.foo.com/x" },
      });
    }

    const forbidden = await t.app.inject({
      method: "GET",
      url: "/api/v1/csp/violations",
      headers: owner,
    });
    expect(forbidden.statusCode).toBe(403);

    const res = await t.app.inject({
      method: "GET",
      url: "/api/v1/csp/violations",
      headers: admin,
    });
    expect(res.statusCode).toBe(200);
    const mine = res.json().violations.find((v: { appSlug: string }) => v.appSlug === slug);
    expect(mine).toMatchObject({
      directive: "connect-src",
      blockedUri: "https://api.foo.com/x",
      count: 2,
      resolved: false, // origin not in the app's manifest
    });
  });

  it("marks a violation resolved only when the current manifest permits that directive", async () => {
    const slug = uniqueSlug();
    const created = await t.app.inject({
      method: "POST",
      url: "/api/v1/apps",
      headers: owner,
      payload: { slug, displayName: "r" },
    });
    const appId = created.json().id as string;

    // The app's manifest now grants this origin (an externalOrigins entry).
    await t.prisma.app.update({
      where: { id: appId },
      data: { capabilities: { externalOrigins: ["https://granted.example"] } },
    });

    // connect-src to the granted origin → resolved (the grant widens connect-src).
    // script-src to the SAME origin → not resolved (externalOrigins doesn't widen it).
    // connect-src to an un-granted origin → not resolved.
    await t.prisma.cspReport.create({
      data: { appId, directive: "connect-src", blockedUri: "https://granted.example/api" },
    });
    await t.prisma.cspReport.create({
      data: { appId, directive: "script-src", blockedUri: "https://granted.example/lib.js" },
    });
    await t.prisma.cspReport.create({
      data: { appId, directive: "connect-src", blockedUri: "https://other.example/x" },
    });

    const res = await t.app.inject({
      method: "GET",
      url: "/api/v1/csp/violations",
      headers: admin,
    });
    expect(res.statusCode).toBe(200);
    const mine = (
      res.json().violations as Array<{
        appSlug: string;
        directive: string;
        blockedUri: string;
        resolved: boolean;
      }>
    ).filter((v) => v.appSlug === slug);

    const find = (directive: string, blockedUri: string) =>
      mine.find((v) => v.directive === directive && v.blockedUri === blockedUri);

    expect(find("connect-src", "https://granted.example/api")?.resolved).toBe(true);
    expect(find("script-src", "https://granted.example/lib.js")?.resolved).toBe(false);
    expect(find("connect-src", "https://other.example/x")?.resolved).toBe(false);
  });

  it("resolves img-src only when the origin is granted; never object-src", async () => {
    const slug = uniqueSlug();
    const created = await t.app.inject({
      method: "POST",
      url: "/api/v1/apps",
      headers: owner,
      payload: { slug, displayName: "img" },
    });
    const appId = created.json().id as string;

    await t.prisma.app.update({
      where: { id: appId },
      data: { capabilities: { externalOrigins: ["https://granted.example"] } },
    });

    await t.prisma.cspReport.create({
      data: { appId, directive: "img-src", blockedUri: "https://granted.example/pic.png" },
    });
    await t.prisma.cspReport.create({
      data: { appId, directive: "img-src", blockedUri: "https://other.example/pic.png" },
    });
    await t.prisma.cspReport.create({
      data: { appId, directive: "object-src", blockedUri: "https://granted.example/x.swf" },
    });
    await t.prisma.cspReport.create({
      data: { appId, directive: "img-src", blockedUri: "data" },
    });

    const res = await t.app.inject({
      method: "GET",
      url: "/api/v1/csp/violations",
      headers: admin,
    });
    expect(res.statusCode).toBe(200);
    const mine = (
      res.json().violations as Array<{
        appSlug: string;
        directive: string;
        blockedUri: string;
        resolved: boolean;
      }>
    ).filter((v) => v.appSlug === slug);

    const find = (directive: string, blockedUri: string) =>
      mine.find((v) => v.directive === directive && v.blockedUri === blockedUri);

    expect(find("img-src", "https://granted.example/pic.png")?.resolved).toBe(true);
    expect(find("img-src", "https://other.example/pic.png")?.resolved).toBe(false);
    expect(find("object-src", "https://granted.example/x.swf")?.resolved).toBe(false);
    expect(find("img-src", "data")?.resolved).toBe(false);
  });
});

describe("POST /api/v1/apps/:slug/access/origin", () => {
  it("opens a med-risk origin-grant request through the write-gate", async () => {
    const slug = uniqueSlug();
    const created = await t.app.inject({
      method: "POST",
      url: "/api/v1/apps",
      headers: owner,
      payload: { slug, displayName: "og" },
    });

    const res = await t.app.inject({
      method: "POST",
      url: `/api/v1/apps/${slug}/access/origin`,
      headers: owner,
      payload: { origin: "https://api.foo.com" },
    });
    expect(res.statusCode).toBe(200);
    expect(typeof res.json().pending).toBe("string");
    // Not applied until approved.
    expect(res.json().manifest.capabilities.externalOrigins).toEqual([]);

    const reqs = await t.prisma.approvalRequest.findMany({
      where: { appId: created.json().id },
    });
    expect(reqs).toHaveLength(1);
    expect(reqs[0]?.risk).toBe("med");
  });
});
