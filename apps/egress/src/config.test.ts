import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { DEFAULT_STATEMENT_TIMEOUT_MS } from "./pool.js";

/**
 * The dev seams are the point of this file: both open a control ADR-0005 rests
 * on, on the plane that holds plaintext connection secrets, and neither one
 * changes any observable behaviour when it is wrongly set — so the boot-fail is
 * the only thing that surfaces it.
 */
const ENV = {
  HELIX_INSTRUCTION_SECRET: "0123456789abcdef0123456789abcdef",
  HELIX_EXCHANGE_SECRET: "abcdef0123456789abcdef0123456789",
  EGRESS_DATABASE_URL: "postgres://helix_egress:helix_egress@db:5432/helix",
};

describe("loadConfig", () => {
  it("defaults both dev seams off", () => {
    const config = loadConfig(ENV);
    expect(config.allowPrivate).toBe(false);
    expect(config.allowInsecureConnection).toBe(false);
  });

  it("opens the dev seams only on an exact 'true'", () => {
    const on = loadConfig({
      ...ENV,
      EGRESS_ALLOW_PRIVATE: "true",
      EGRESS_ALLOW_INSECURE_CONNECTION: "true",
    });
    expect(on.allowPrivate).toBe(true);
    expect(on.allowInsecureConnection).toBe(true);

    // "Allow" polarity, default off — anything truthy-but-not-"true" stays shut.
    const fuzzy = loadConfig({
      ...ENV,
      EGRESS_ALLOW_PRIVATE: "1",
      EGRESS_ALLOW_INSECURE_CONNECTION: "yes",
    });
    expect(fuzzy.allowPrivate).toBe(false);
    expect(fuzzy.allowInsecureConnection).toBe(false);
  });

  it("refuses EGRESS_ALLOW_PRIVATE in production", () => {
    expect(() =>
      loadConfig({ ...ENV, EGRESS_ALLOW_PRIVATE: "true", NODE_ENV: "production" }),
    ).toThrow(/EGRESS_ALLOW_PRIVATE.*refused in production/);
  });

  it("refuses EGRESS_ALLOW_INSECURE_CONNECTION in production", () => {
    expect(() =>
      loadConfig({ ...ENV, EGRESS_ALLOW_INSECURE_CONNECTION: "true", NODE_ENV: "production" }),
    ).toThrow(/EGRESS_ALLOW_INSECURE_CONNECTION.*refused in production/);
  });

  it("boots in production with both unset", () => {
    const config = loadConfig({ ...ENV, NODE_ENV: "production" });
    expect(config.allowPrivate).toBe(false);
    expect(config.allowInsecureConnection).toBe(false);
  });

  it("throws a clear error on missing requirements", () => {
    expect(() => loadConfig({})).toThrow(/HELIX_INSTRUCTION_SECRET is required/);
    expect(() => loadConfig({ HELIX_INSTRUCTION_SECRET: "short" })).toThrow(/at least 32 bytes/);
    // Both seam keys are required before the DSN check.
    expect(() => loadConfig({ HELIX_INSTRUCTION_SECRET: ENV.HELIX_INSTRUCTION_SECRET })).toThrow(
      /HELIX_EXCHANGE_SECRET is required/,
    );
    expect(() =>
      loadConfig({
        HELIX_INSTRUCTION_SECRET: ENV.HELIX_INSTRUCTION_SECRET,
        HELIX_EXCHANGE_SECRET: ENV.HELIX_EXCHANGE_SECRET,
      }),
    ).toThrow(/EGRESS_DATABASE_URL or DATABASE_URL is required/);
  });

  // The portal→egress exchange-JWT key. Verify side, so it is
  // required exactly like the instruction secret, in dev too: the exchange
  // route has no degraded mode that still serves it.
  describe("HELIX_EXCHANGE_SECRET", () => {
    it("is required, and parsed onto the config", () => {
      expect(() => loadConfig({ ...ENV, HELIX_EXCHANGE_SECRET: undefined })).toThrow(
        /HELIX_EXCHANGE_SECRET is required/,
      );
      expect(loadConfig(ENV).exchangeSecret).toEqual(Buffer.from(ENV.HELIX_EXCHANGE_SECRET));
    });

    it("refuses a too-short value (would weaken the derived key)", () => {
      expect(() => loadConfig({ ...ENV, HELIX_EXCHANGE_SECRET: "short" })).toThrow(
        /HELIX_EXCHANGE_SECRET must be at least 32 bytes/,
      );
    });
  });

  // ADR-0002 ISSUE-05 — the per-query ceiling both egress pools get from
  // `createEgressPool`; config only resolves the knob, the factory applies it.
  it("defaults statementTimeoutMs to the shared factory default and honors EGRESS_STATEMENT_TIMEOUT_MS", () => {
    expect(loadConfig(ENV).statementTimeoutMs).toBe(DEFAULT_STATEMENT_TIMEOUT_MS);
    expect(loadConfig({ ...ENV, EGRESS_STATEMENT_TIMEOUT_MS: "3000" }).statementTimeoutMs).toBe(
      3000,
    );
  });

  // The provider cache's reconcile cadence: the self-heal that
  // bounds staleness after a missed NOTIFY. A non-positive value would coerce
  // to a hot reconcile loop in `setTimeout`, so it boots noisily instead.
  it("defaults the provider reconcile interval to 60s and honors EGRESS_PROVIDERS_RECONCILE_INTERVAL_MS", () => {
    expect(loadConfig(ENV).providersReconcileIntervalMs).toBe(60_000);
    expect(
      loadConfig({ ...ENV, EGRESS_PROVIDERS_RECONCILE_INTERVAL_MS: "5000" })
        .providersReconcileIntervalMs,
    ).toBe(5000);
    for (const bad of ["0", "-1", "NaN", "Infinity", "abc"]) {
      expect(() => loadConfig({ ...ENV, EGRESS_PROVIDERS_RECONCILE_INTERVAL_MS: bad })).toThrow(
        /EGRESS_PROVIDERS_RECONCILE_INTERVAL_MS/,
      );
    }
  });

  // The retirement sweep's cadence, validated by the
  // same requirePositiveMs rail: a hot zero loop or a NaN coerced to ~0ms
  // would hammer the ledger read. The default (60s) sits well inside
  // the 15-minute recovery bound (ADR-0031 amendment item 12).
  it("defaults the retirement sweep interval to 60s and honors EGRESS_RETIRE_SWEEP_INTERVAL_MS", () => {
    expect(loadConfig(ENV).retireSweepIntervalMs).toBe(60_000);
    expect(
      loadConfig({ ...ENV, EGRESS_RETIRE_SWEEP_INTERVAL_MS: "30000" }).retireSweepIntervalMs,
    ).toBe(30_000);
    for (const bad of ["0", "-1", "NaN", "Infinity", "abc"]) {
      expect(() => loadConfig({ ...ENV, EGRESS_RETIRE_SWEEP_INTERVAL_MS: bad })).toThrow(
        /EGRESS_RETIRE_SWEEP_INTERVAL_MS/,
      );
    }
  });

  // ADR-0046 — the keyless list is empty by default (resolution stays DB-only)
  // and malformed entries are boot errors, never silently dropped rules.
  describe("EGRESS_MANAGED_IDENTITY_CONNECTIONS", () => {
    it("defaults to no managed-identity connections", () => {
      expect(loadConfig(ENV).managedIdentityConnections).toEqual([]);
      expect(
        loadConfig({ ...ENV, EGRESS_MANAGED_IDENTITY_CONNECTIONS: "  " })
          .managedIdentityConnections,
      ).toEqual([]);
    });

    it("parses name=host-suffix pairs, lowercasing the suffix", () => {
      const config = loadConfig({
        ...ENV,
        EGRESS_MANAGED_IDENTITY_CONNECTIONS:
          "foundry=Services.AI.Azure.com, contoso=contoso.openai.azure.com",
      });
      expect(config.managedIdentityConnections).toEqual([
        { connection: "foundry", hostSuffix: "services.ai.azure.com" },
        { connection: "contoso", hostSuffix: "contoso.openai.azure.com" },
      ]);
    });

    it.each([
      ["foundry", "missing the =host-suffix half"],
      ["foundry=", "empty suffix"],
      ["foundry=.services.ai.azure.com", "leading-dot suffix"],
      ["foundry=com", "bare TLD — would match the world"],
      ["foundry=https://services.ai.azure.com", "a URL, not a host suffix"],
      ["Foundry=services.ai.azure.com", "a non-kebab connection name"],
      ["foundry=services.ai.azure.com,foundry=openai.azure.com", "a duplicate connection"],
    ])("refuses malformed entry %s (%s)", (value) => {
      expect(() => loadConfig({ ...ENV, EGRESS_MANAGED_IDENTITY_CONNECTIONS: value })).toThrow(
        /EGRESS_MANAGED_IDENTITY_CONNECTIONS/,
      );
    });
  });

  // ADR-0046 — the audience override is a spike/sovereign escape hatch, and
  // it is validated like one: a bare https origin, or boot fails.
  describe("EGRESS_EXTRA_BLOCKED_CIDRS", () => {
    it("defaults to no extra ranges when unset or whitespace-only", () => {
      expect(loadConfig(ENV).extraBlockedCidrs).toEqual([]);
      expect(loadConfig({ ...ENV, EGRESS_EXTRA_BLOCKED_CIDRS: "  " }).extraBlockedCidrs).toEqual(
        [],
      );
    });

    it("parses comma-separated v4 and v6 CIDRs", () => {
      const config = loadConfig({
        ...ENV,
        EGRESS_EXTRA_BLOCKED_CIDRS: "203.0.113.0/24, 2001:db9::/32",
      });
      expect(config.extraBlockedCidrs).toHaveLength(2);
      expect(config.extraBlockedCidrs[0]).toEqual({
        family: 4,
        base: expect.any(Number),
        bits: 24,
      });
      expect(config.extraBlockedCidrs[1]).toEqual({
        family: 6,
        base: expect.any(BigInt),
        bits: 32,
      });
    });

    it.each([
      "10.0.0.0",
      "10.0.0.0/33",
      "2001:db9::/129",
      "nope/8",
      "10.0.0.0/x",
      "10.0.0.0/0",
      "10.0.0.0/8,,10.1.0.0/16",
      "fe80::1%eth0/64",
    ])("refuses malformed value %s", (value) => {
      expect(() => loadConfig({ ...ENV, EGRESS_EXTRA_BLOCKED_CIDRS: value })).toThrow(
        /EGRESS_EXTRA_BLOCKED_CIDRS/,
      );
    });

    it("still refuses EGRESS_ALLOW_PRIVATE in production when extra ranges are set", () => {
      expect(() =>
        loadConfig({
          ...ENV,
          EGRESS_ALLOW_PRIVATE: "true",
          EGRESS_EXTRA_BLOCKED_CIDRS: "10.9.0.0/16",
          NODE_ENV: "production",
        }),
      ).toThrow(/EGRESS_ALLOW_PRIVATE.*refused in production/);
    });

    it("boots in production with a valid extra list when allowPrivate is unset", () => {
      const config = loadConfig({
        ...ENV,
        EGRESS_EXTRA_BLOCKED_CIDRS: "10.9.0.0/16",
        NODE_ENV: "production",
      });
      expect(config.extraBlockedCidrs).toHaveLength(1);
      expect(config.extraBlockedCidrs[0]?.family).toBe(4);
      expect(config.extraBlockedCidrs[0]?.bits).toBe(16);
    });
  });

  describe("EGRESS_MANAGED_IDENTITY_RESOURCE", () => {
    it("defaults to undefined (the Foundry audience constant applies)", () => {
      expect(loadConfig(ENV).managedIdentityResource).toBeUndefined();
    });

    it("accepts a bare https origin and normalises it", () => {
      const config = loadConfig({
        ...ENV,
        EGRESS_MANAGED_IDENTITY_RESOURCE: "https://cognitiveservices.azure.com/",
      });
      expect(config.managedIdentityResource).toBe("https://cognitiveservices.azure.com");
    });

    it.each([
      ["http://ai.azure.com", "not https"],
      ["https://ai.azure.com/.default", "a path (the MI endpoint wants the bare resource)"],
      ["https://ai.azure.com?x=1", "a query"],
      ["not a url", "unparseable"],
    ])("refuses %s (%s)", (value) => {
      expect(() => loadConfig({ ...ENV, EGRESS_MANAGED_IDENTITY_RESOURCE: value })).toThrow(
        /EGRESS_MANAGED_IDENTITY_RESOURCE/,
      );
    });
  });
});
