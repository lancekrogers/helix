import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DeploymentConfigResponseSchema } from "@azx-pbc/shared";
import { buildTestApp, type TestApp } from "../test/harness.js";
import { withEnv } from "../test/env.js";

/**
 * GET /api/v1/config — the deployment bootstrap the prebuilt SPA reads its
 * topology from. Env is read per request, so these override it around an inject
 * (same pattern as dashboard.test.ts) rather than rebuilding the app.
 */
let t: TestApp;

beforeAll(async () => {
  t = buildTestApp();
  await t.app.ready();
});

afterAll(async () => {
  await t.close();
});

describe("GET /api/v1/config", () => {
  it("is public — no bearer token required", async () => {
    const res = await t.app.inject({ url: "/api/v1/config" });
    expect(res.statusCode).toBe(200);
    const body = DeploymentConfigResponseSchema.parse(res.json());
    expect(body.appPublicBase).toBe("https://local.helix.azxlabs.io:8080");
  });

  it("reports the deployment's apps base", async () => {
    await withEnv({ APP_PUBLIC_BASE: "https://apps.example.com" }, async () => {
      const res = await t.app.inject({ url: "/api/v1/config" });
      expect(res.json<{ appPublicBase: string }>().appPublicBase).toBe("https://apps.example.com");
    });
  });

  it("does not expose the control domain in the config payload", async () => {
    await withEnv(
      {
        APP_PUBLIC_BASE: "https://apps.example.com",
        CONTROL_PUBLIC_BASE: "https://control.example.com",
      },
      async () => {
        const res = await t.app.inject({ url: "/api/v1/config" });
        expect(res.json<{ appPublicBase: string }>().appPublicBase).toBe(
          "https://apps.example.com",
        );
        expect(JSON.stringify(res.json())).not.toContain("control.example.com");
      },
    );
  });

  describe("deploy size caps", () => {
    it("reports the defaults in megabytes", async () => {
      await withEnv(
        { DEPLOY_MAX_FILE_MB: undefined, DEPLOY_MAX_BUNDLE_MB: undefined },
        async () => {
          const body = DeploymentConfigResponseSchema.parse(
            (await t.app.inject({ url: "/api/v1/config" })).json(),
          );
          expect(body.deployMaxFileMb).toBe(50);
          expect(body.deployMaxBundleMb).toBe(250);
        },
      );
    });

    // The SPA renders these into the agent skill, so an override has to reach the
    // client — a stale cap sends an agent chasing a rejection it can't explain.
    it("follows the env overrides", async () => {
      await withEnv({ DEPLOY_MAX_FILE_MB: "80", DEPLOY_MAX_BUNDLE_MB: "400" }, async () => {
        const body = DeploymentConfigResponseSchema.parse(
          (await t.app.inject({ url: "/api/v1/config" })).json(),
        );
        expect(body.deployMaxFileMb).toBe(80);
        expect(body.deployMaxBundleMb).toBe(400);
      });
    });
  });

  // Unlike /api/v1/auth/config, which 404s without an IdP. Coupling the apps
  // domain to OIDC config would leave a dev-token-only portal's SPA with no base.
  it("still answers when the portal has no OIDC configured", async () => {
    const devOnly = buildTestApp({ auth: { publicConfig: null } });
    try {
      await devOnly.app.ready();
      expect((await devOnly.app.inject({ url: "/api/v1/auth/config" })).statusCode).toBe(404);
      expect((await devOnly.app.inject({ url: "/api/v1/config" })).statusCode).toBe(200);
    } finally {
      await devOnly.close();
    }
  });

  describe("the opt-in dev gateway", () => {
    it("omits devApiBase when it isn't deployed", async () => {
      await withEnv({ DEV_API_PUBLIC_BASE: undefined }, async () => {
        const body = (await t.app.inject({ url: "/api/v1/config" })).json<
          Record<string, unknown>
        >();
        expect(body.devApiBase).toBeUndefined();
      });
    });

    // The Bicep passes '' when deployDevGateway is false.
    it("treats an empty value as not deployed", async () => {
      await withEnv({ DEV_API_PUBLIC_BASE: "" }, async () => {
        const body = (await t.app.inject({ url: "/api/v1/config" })).json<
          Record<string, unknown>
        >();
        expect(body.devApiBase).toBeUndefined();
      });
    });

    it("reports devApiBase when it is deployed", async () => {
      await withEnv({ DEV_API_PUBLIC_BASE: "https://dev-api.apps.example.com" }, async () => {
        const body = (await t.app.inject({ url: "/api/v1/config" })).json<{
          devApiBase: string;
        }>();
        expect(body.devApiBase).toBe("https://dev-api.apps.example.com");
      });
    });
  });

  describe("the platform spend cap", () => {
    it("is omitted when unset or zero", async () => {
      for (const value of [undefined, "0"]) {
        await withEnv({ PLATFORM_MONTHLY_USD_CAP: value }, async () => {
          const body = (await t.app.inject({ url: "/api/v1/config" })).json<
            Record<string, unknown>
          >();
          expect(body.platformMonthlyUsdCap).toBeUndefined();
        });
      }
    });

    it("is reported when configured", async () => {
      await withEnv({ PLATFORM_MONTHLY_USD_CAP: "2500" }, async () => {
        const body = (await t.app.inject({ url: "/api/v1/config" })).json<{
          platformMonthlyUsdCap: number;
        }>();
        expect(body.platformMonthlyUsdCap).toBe(2500);
      });
    });
  });
});
