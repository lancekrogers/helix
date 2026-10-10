import { afterEach, describe, expect, it, vi } from "vitest";
import { CliError, PortalClient } from "./client.js";

/**
 * The portal gates **reads** as well as writes (ADR-0024) — only `/health` and
 * the auth-config bootstrap are public. So every client method except
 * `getAuthConfig` must send a bearer token, and a method that forgets to is
 * indistinguishable from "not signed in" at the CLI. `listVersions` shipped
 * exactly that way, which is what this table exists to prevent recurring.
 */

/** Records the requests a client makes, replying with `body` each time. */
function stubFetch(body: unknown, status = 200) {
  const calls: { url: string; init: RequestInit }[] = [];
  const spy = vi
    .spyOn(globalThis, "fetch")
    .mockImplementation(async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      return new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });
    });
  return { calls, spy };
}

function authHeader(init: RequestInit): string | undefined {
  return (init.headers as Record<string, string> | undefined)?.authorization;
}

const APP = {
  id: "11111111-1111-4111-8111-111111111111",
  slug: "demo",
  displayName: "Demo",
  visibility: { mode: "internal" as const },
  currentVersionId: null,
  archivedAt: null,
  createdAt: "2026-07-30T00:00:00.000Z",
  updatedAt: "2026-07-30T00:00:00.000Z",
};

afterEach(() => vi.restoreAllMocks());

describe("PortalClient authentication", () => {
  const authed: [string, (c: PortalClient) => Promise<unknown>, unknown][] = [
    [
      "me",
      (c) => c.me(),
      { sub: "u1", via: "oidc", email: "e@x.io", isAdmin: false, canSearchDirectory: true },
    ],
    ["getSkill", (c) => c.getSkill(), "# Helix skill\n"],
    ["listVersions", (c) => c.listVersions("demo"), []],
    [
      "createApp",
      (c) => c.createApp({ slug: "demo", displayName: "Demo" }),
      { ...APP, applied: [], pending: null },
    ],
    ["promote", (c) => c.promote("demo", 1), APP],
    ["rollback", (c) => c.rollback("demo"), APP],
  ];

  it.each(authed)("%s sends a bearer token", async (_name, call, body) => {
    const { calls } = stubFetch(body);
    await call(new PortalClient("http://portal", "tok"));
    expect(calls).toHaveLength(1);
    expect(authHeader(calls[0]!.init)).toBe("Bearer tok");
  });

  it.each(authed)("%s fails closed when there is no token", async (_name, call, body) => {
    stubFetch(body);
    await expect(call(new PortalClient("http://portal"))).rejects.toThrow(/not signed in/);
  });

  it("getAuthConfig stays public — it is how the CLI discovers the issuer", async () => {
    const { calls } = stubFetch({ issuer: "http://idp", cliClientId: "azx-cli" });
    await new PortalClient("http://portal").getAuthConfig();
    expect(authHeader(calls[0]!.init)).toBeUndefined();
  });

  it("getSkill sends a bearer token and returns the markdown body", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      calls.push({ url: String(input), init: init ?? {} });
      return new Response("# Helix skill\n", {
        status: 200,
        headers: { "content-type": "text/markdown" },
      });
    });
    const skill = await new PortalClient("http://portal", "tok").getSkill();
    expect(skill).toBe("# Helix skill\n");
    expect(calls[0]!.url).toBe("http://portal/api/v1/skill");
    expect(authHeader(calls[0]!.init)).toBe("Bearer tok");
  });

  it("getSkill surfaces the portal's error code on a non-ok response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: { code: "unauthorized", message: "no token" } }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
    );
    await expect(new PortalClient("http://portal", "tok").getSkill()).rejects.toMatchObject({
      code: "unauthorized",
    });
  });
});

describe("PortalClient error handling", () => {
  it("surfaces the portal's error code", async () => {
    stubFetch({ error: { code: "slug_taken", message: 'slug "demo" is already taken' } }, 409);
    await expect(
      new PortalClient("http://portal", "tok").createApp({ slug: "demo", displayName: "Demo" }),
    ).rejects.toMatchObject({ code: "slug_taken" });
  });

  it("falls back to the status when the body is not an ApiError", async () => {
    stubFetch({ nope: true }, 502);
    await expect(new PortalClient("http://portal", "tok").me()).rejects.toThrow(
      new CliError("request failed (HTTP 502)"),
    );
  });
});
