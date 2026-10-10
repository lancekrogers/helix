import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { classifyHost, RESERVED_SUBDOMAINS } from "./routing/hosts.js";
import {
  controlOrigin,
  loadConfig,
  loadDevGatewayConfig,
  parseConnectionString,
  publicOrigin,
} from "./config.js";

// The well-known Azurite dev credentials (public, not a secret).
const AZURITE_KEY =
  "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
const AZURITE_CS =
  `DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=${AZURITE_KEY};` +
  "BlobEndpoint=http://azurite:10000/devstoreaccount1;QueueEndpoint=http://azurite:10001/devstoreaccount1";

// Managed-identity blob env (the prod path): endpoint + client_id select it, and
// the IDENTITY_* pair is what Container Apps injects when the MI is attached.
const MI_BLOB_ENV = {
  AZURE_STORAGE_BLOB_ENDPOINT: "https://prodacct.blob.core.windows.net",
  AZURE_CLIENT_ID: "11111111-1111-1111-1111-111111111111",
  IDENTITY_ENDPOINT: "http://169.254.169.254/msi/token",
  IDENTITY_HEADER: "identity-header-value",
};

describe("parseConnectionString", () => {
  it("parses the Azurite connection string (key contains '=', BlobEndpoint wins)", () => {
    const parsed = parseConnectionString(AZURITE_CS);
    expect(parsed.accountName).toBe("devstoreaccount1");
    expect(parsed.accountKey).toEqual(Buffer.from(AZURITE_KEY, "base64"));
    expect(parsed.blobEndpoint).toBe("http://azurite:10000/devstoreaccount1");
  });

  it("derives the Azure endpoint when BlobEndpoint is absent", () => {
    const parsed = parseConnectionString(
      `DefaultEndpointsProtocol=https;AccountName=prodacct;AccountKey=${AZURITE_KEY};EndpointSuffix=core.windows.net`,
    );
    expect(parsed.blobEndpoint).toBe("https://prodacct.blob.core.windows.net");
  });

  it("rejects a connection string without an account key", () => {
    expect(() => parseConnectionString("AccountName=x;BlobEndpoint=http://h")).toThrow();
  });
});

describe("loadConfig", () => {
  // The platform is HTTPS-only, so dev config must carry TLS material.
  const ENV = {
    DATABASE_URL: "postgresql://helix:helix@db:5432/helix",
    EDGE_DATABASE_URL: "postgresql://helix_edge:helix_edge@db:5432/helix",
    AZURE_STORAGE_CONNECTION_STRING: AZURITE_CS,
    EDGE_TLS_CERT_FILE: "/certs/local-helix.pem",
    EDGE_TLS_KEY_FILE: "/certs/local-helix-key.pem",
  };

  it("applies defaults and the fail-closed auth flag", () => {
    const config = loadConfig({ ...ENV });
    expect(config.baseDomain).toBe("local.helix.azxlabs.io");
    expect(config.blob.provider).toBe("azure");
    expect(config.blob.container).toBe("app-bundles");
    expect(config.allowUnauthenticated).toBe(false);
    expect(config.reconcileIntervalMs).toBe(60_000);
    expect(config.statementTimeoutMs).toBe(10_000);
    expect(config.auth).toBeNull();
    expect(config.tls).toEqual({
      certFile: "/certs/local-helix.pem",
      keyFile: "/certs/local-helix-key.pem",
    });
    expect(config.publicScheme).toBe("https");
    expect(config.publicPort).toBe(8080);
    // "Allow" polarity, default off: both open surfaces forbidden unless opted in.
    expect(config.allowPublicApps).toBe(false);
    expect(config.allowPasswordApps).toBe(false);
  });

  it("permits open surfaces only on an explicit 'true' (EDGE_ALLOW_*_APPS)", () => {
    const config = loadConfig({
      ...ENV,
      EDGE_ALLOW_PUBLIC_APPS: "true",
      EDGE_ALLOW_PASSWORD_APPS: "true",
    });
    expect(config.allowPublicApps).toBe(true);
    expect(config.allowPasswordApps).toBe(true);
    // Any other value (or unset) leaves the surface forbidden.
    expect(loadConfig({ ...ENV, EDGE_ALLOW_PUBLIC_APPS: "1" }).allowPublicApps).toBe(false);
  });

  it("honors overrides", () => {
    const config = loadConfig({
      ...ENV,
      EDGE_BASE_DOMAIN: "AZX.Helix.AzxLabs.io",
      BLOB_CONTAINER: "bundles",
      EDGE_DEV_ALLOW_UNAUTHENTICATED: "true",
      EDGE_RECONCILE_INTERVAL_MS: "5000",
      EDGE_STATEMENT_TIMEOUT_MS: "3000",
    });
    expect(config.baseDomain).toBe("azx.helix.azxlabs.io");
    expect(config.blob.container).toBe("bundles");
    expect(config.allowUnauthenticated).toBe(true);
    expect(config.reconcileIntervalMs).toBe(5000);
    expect(config.statementTimeoutMs).toBe(3000);
  });

  // A bare Number() let NaN through, and NaN reaches setTimeout, which coerces it
  // to ~0 ms — a DB hot loop from every replica, with /health reading `ok`
  // throughout because the loads keep succeeding. Fail the boot instead.
  it("refuses an unusable EDGE_RECONCILE_INTERVAL_MS instead of hot-looping", () => {
    for (const bad of ["abc", "0", "-1", "NaN", "Infinity"]) {
      expect(() => loadConfig({ ...ENV, EDGE_RECONCILE_INTERVAL_MS: bad })).toThrow(
        /EDGE_RECONCILE_INTERVAL_MS must be a positive number/,
      );
    }
    // Unset falls back to the documented default; an explicit value is honored.
    expect(loadConfig({ ...ENV }).reconcileIntervalMs).toBe(60_000);
    // Empty/whitespace counts as unset, not as a bad value: compose and CI pass
    // empty strings for vars that are declared but not set, and `??` wouldn't
    // catch those (`Number("")` is 0).
    for (const blank of ["", "   "]) {
      expect(loadConfig({ ...ENV, EDGE_RECONCILE_INTERVAL_MS: blank }).reconcileIntervalMs).toBe(
        60_000,
      );
    }
    expect(loadConfig({ ...ENV, EDGE_RECONCILE_INTERVAL_MS: "2500" }).reconcileIntervalMs).toBe(
      2500,
    );
  });

  it("applies the same validation to the dev-gateway, which shares the parse", () => {
    expect(() =>
      loadDevGatewayConfig({
        ...ENV,
        EDGE_DEV_DATABASE_URL: "postgresql://helix_dev:helix_dev@db:5432/helix",
        EDGE_RECONCILE_INTERVAL_MS: "abc",
      }),
    ).toThrow(/EDGE_RECONCILE_INTERVAL_MS must be a positive number/);
  });

  it("parses EDGE_LLM_PLATFORM_DOLLARS_PER_DAY with the same rules as other gateway knobs", () => {
    for (const bad of ["abc", "-1", "NaN", "Infinity"]) {
      expect(() => loadConfig({ ...ENV, EDGE_LLM_PLATFORM_DOLLARS_PER_DAY: bad })).toThrow(
        /EDGE_LLM_PLATFORM_DOLLARS_PER_DAY must be a non-negative number/,
      );
    }
    expect(loadConfig({ ...ENV }).llm.platformDollarsPerDay).toBe(0);
    expect(
      loadConfig({ ...ENV, EDGE_LLM_PLATFORM_DOLLARS_PER_DAY: "100" }).llm.platformDollarsPerDay,
    ).toBe(100);
    expect(
      loadConfig({ ...ENV, EDGE_LLM_PLATFORM_DOLLARS_PER_DAY: "0" }).llm.platformDollarsPerDay,
    ).toBe(0);
    for (const blank of ["", "   "]) {
      expect(
        loadConfig({ ...ENV, EDGE_LLM_PLATFORM_DOLLARS_PER_DAY: blank }).llm.platformDollarsPerDay,
      ).toBe(0);
    }
    expect(() =>
      loadDevGatewayConfig({
        ...ENV,
        EDGE_DEV_DATABASE_URL: "postgresql://helix_dev:helix_dev@db:5432/helix",
        EDGE_LLM_PLATFORM_DOLLARS_PER_DAY: "abc",
      }),
    ).toThrow(/EDGE_LLM_PLATFORM_DOLLARS_PER_DAY must be a non-negative number/);
  });

  it("parses EDGE_LLM_DEFAULT_DOLLARS_PER_DAY with the same rules as other gateway knobs", () => {
    for (const bad of ["abc", "-1", "NaN", "Infinity"]) {
      expect(() => loadConfig({ ...ENV, EDGE_LLM_DEFAULT_DOLLARS_PER_DAY: bad })).toThrow(
        /EDGE_LLM_DEFAULT_DOLLARS_PER_DAY must be a non-negative number/,
      );
    }
    expect(loadConfig({ ...ENV }).llm.defaultDollarsPerDay).toBe(50);
    expect(
      loadConfig({ ...ENV, EDGE_LLM_DEFAULT_DOLLARS_PER_DAY: "120" }).llm.defaultDollarsPerDay,
    ).toBe(120);
    expect(
      loadConfig({ ...ENV, EDGE_LLM_DEFAULT_DOLLARS_PER_DAY: "0" }).llm.defaultDollarsPerDay,
    ).toBe(0);
    for (const blank of ["", "   "]) {
      expect(
        loadConfig({ ...ENV, EDGE_LLM_DEFAULT_DOLLARS_PER_DAY: blank }).llm.defaultDollarsPerDay,
      ).toBe(50);
    }
    expect(() =>
      loadDevGatewayConfig({
        ...ENV,
        EDGE_DEV_DATABASE_URL: "postgresql://helix_dev:helix_dev@db:5432/helix",
        EDGE_LLM_DEFAULT_DOLLARS_PER_DAY: "abc",
      }),
    ).toThrow(/EDGE_LLM_DEFAULT_DOLLARS_PER_DAY must be a non-negative number/);
  });

  it("parses LLM concurrency caps and the call deadline", () => {
    expect(loadConfig({ ...ENV }).llm.maxAppInFlight).toBe(10);
    expect(loadConfig({ ...ENV }).llm.maxUserInFlight).toBe(3);
    expect(loadConfig({ ...ENV }).llm.maxInFlight).toBe(200);
    expect(loadConfig({ ...ENV }).llm.maxCallMs).toBe(600_000);
    expect(loadConfig({ ...ENV, EDGE_LLM_MAX_APP_IN_FLIGHT: "0" }).llm.maxAppInFlight).toBe(0);
    for (const [key, field] of [
      ["EDGE_LLM_MAX_APP_IN_FLIGHT", "maxAppInFlight"],
      ["EDGE_LLM_MAX_USER_IN_FLIGHT", "maxUserInFlight"],
      ["EDGE_LLM_MAX_IN_FLIGHT", "maxInFlight"],
    ] as const) {
      for (const bad of ["-1", "2.5", "abc", "NaN", "Infinity"]) {
        expect(() => loadConfig({ ...ENV, [key]: bad })).toThrow(
          new RegExp(`${key} must be a non-negative integer`),
        );
      }
      expect(loadConfig({ ...ENV, [key]: "12" }).llm[field]).toBe(12);
    }
    for (const bad of ["0", "-1", "abc"]) {
      expect(() => loadConfig({ ...ENV, EDGE_LLM_MAX_CALL_MS: bad })).toThrow(
        /EDGE_LLM_MAX_CALL_MS must be a positive number/,
      );
    }
    expect(() => loadConfig({ ...ENV, EDGE_LLM_MAX_CALL_MS: String(2_147_483_648) })).toThrow(
      /EDGE_LLM_MAX_CALL_MS must be at most 2147483647/,
    );
    expect(loadConfig({ ...ENV, EDGE_LLM_MAX_CALL_MS: "2147483647" }).llm.maxCallMs).toBe(
      2_147_483_647,
    );
    expect(() =>
      loadDevGatewayConfig({
        ...ENV,
        EDGE_DEV_DATABASE_URL: "postgresql://helix_dev:helix_dev@db:5432/helix",
        EDGE_LLM_MAX_IN_FLIGHT: "2.5",
      }),
    ).toThrow(/EDGE_LLM_MAX_IN_FLIGHT must be a non-negative integer/);
  });

  it("parses fetch per-app concurrency cap", () => {
    expect(loadConfig({ ...ENV }).fetch.maxAppInFlight).toBe(0);
    expect(loadConfig({ ...ENV, EDGE_FETCH_MAX_APP_IN_FLIGHT: "5" }).fetch.maxAppInFlight).toBe(5);
    for (const bad of ["-1", "2.5", "abc", "NaN", "Infinity"]) {
      expect(() => loadConfig({ ...ENV, EDGE_FETCH_MAX_APP_IN_FLIGHT: bad })).toThrow(
        /EDGE_FETCH_MAX_APP_IN_FLIGHT must be a non-negative integer/,
      );
    }
    expect(() =>
      loadDevGatewayConfig({
        ...ENV,
        EDGE_DEV_DATABASE_URL: "postgresql://helix_dev:helix_dev@db:5432/helix",
        EDGE_FETCH_MAX_APP_IN_FLIGHT: "abc",
      }),
    ).toThrow(/EDGE_FETCH_MAX_APP_IN_FLIGHT must be a non-negative integer/);
  });

  // A hop count trusts by position, so it structurally ignores the peer address
  // and lets anyone reaching the origin directly spoof X-Forwarded-*
  // (GHSA-3m5p-2c4r-xxw2). Fastify 5.12.1 compiles a number to "trust nothing"
  // silently, which would collapse req.ip — and with it the anon limiter, the
  // login throttle and the audit hash — to the ingress address while everything
  // still read green. Fail the boot instead, the same posture the reconcile
  // interval takes above.
  it("parses EDGE_IMG_SRC_ALLOW_ALL with allow polarity", () => {
    expect(loadConfig({ ...ENV }).imgSrcAllowAll).toBe(false);
    expect(loadConfig({ ...ENV, EDGE_IMG_SRC_ALLOW_ALL: "true" }).imgSrcAllowAll).toBe(true);
    for (const bad of ["True", "1", "yes", " true"]) {
      expect(loadConfig({ ...ENV, EDGE_IMG_SRC_ALLOW_ALL: bad }).imgSrcAllowAll).toBe(false);
    }
  });

  it("parses EDGE_IMG_SRC_REPORT_ONLY with allow polarity", () => {
    expect(loadConfig({ ...ENV }).imgSrcReportOnly).toBe(false);
    expect(loadConfig({ ...ENV, EDGE_IMG_SRC_REPORT_ONLY: "true" }).imgSrcReportOnly).toBe(true);
    for (const bad of ["True", "1", "yes", " true"]) {
      expect(loadConfig({ ...ENV, EDGE_IMG_SRC_REPORT_ONLY: bad }).imgSrcReportOnly).toBe(false);
    }
  });

  it("refuses boot when EDGE_IMG_SRC_REPORT_ONLY and EDGE_IMG_SRC_ALLOW_ALL are both true", () => {
    expect(() =>
      loadConfig({
        ...ENV,
        EDGE_IMG_SRC_REPORT_ONLY: "true",
        EDGE_IMG_SRC_ALLOW_ALL: "true",
      }),
    ).toThrow(/EDGE_IMG_SRC_REPORT_ONLY and EDGE_IMG_SRC_ALLOW_ALL cannot both be true/);
  });

  it("parses EDGE_IMG_SRC_EXTRA", () => {
    expect(loadConfig({ ...ENV }).imgSrcExtra).toEqual([]);
    expect(loadConfig({ ...ENV, EDGE_IMG_SRC_EXTRA: "" }).imgSrcExtra).toEqual([]);
    expect(loadConfig({ ...ENV, EDGE_IMG_SRC_EXTRA: "   " }).imgSrcExtra).toEqual([]);
    expect(
      loadConfig({ ...ENV, EDGE_IMG_SRC_EXTRA: "https://a.example, https://b.example:8443" })
        .imgSrcExtra,
    ).toEqual(["https://a.example", "https://b.example:8443"]);
    expect(
      loadConfig({
        ...ENV,
        EDGE_IMG_SRC_EXTRA: "https://a.example,https://a.example",
      }).imgSrcExtra,
    ).toEqual(["https://a.example"]);
    expect(() => loadConfig({ ...ENV, EDGE_IMG_SRC_EXTRA: "wss://live.example" })).toThrow(
      /EDGE_IMG_SRC_EXTRA is not a list of https origins/,
    );
    expect(() => loadConfig({ ...ENV, EDGE_IMG_SRC_EXTRA: "https://x;connect-src" })).toThrow(
      /EDGE_IMG_SRC_EXTRA is not a list of https origins/,
    );
    for (const bad of [
      "http://a.example",
      "https:",
      "*",
      "https://*.a.example",
      "https://a.example/path",
      "https://a.example?x=1",
      "https://u:p@a.example",
      "not a url",
    ]) {
      expect(() => loadConfig({ ...ENV, EDGE_IMG_SRC_EXTRA: bad })).toThrow(
        /EDGE_IMG_SRC_EXTRA is not a list of https origins/,
      );
    }
    expect(() =>
      loadConfig({
        ...ENV,
        EDGE_IMG_SRC_EXTRA: "https://good.example,https://a.example/path",
      }),
    ).toThrow(/EDGE_IMG_SRC_EXTRA is not a list of https origins/);
  });

  it("refuses a hop count for EDGE_TRUST_PROXY instead of silently trusting nothing", () => {
    for (const hops of ["1", "2", " 3 "]) {
      expect(() => loadConfig({ ...ENV, EDGE_TRUST_PROXY: hops })).toThrow(
        /EDGE_TRUST_PROXY no longer accepts a proxy hop count/,
      );
    }
    // The dev-gateway shares the parse, so it fails closed identically.
    expect(() =>
      loadDevGatewayConfig({
        ...ENV,
        EDGE_DEV_DATABASE_URL: "postgresql://helix_dev:helix_dev@db:5432/helix",
        EDGE_TRUST_PROXY: "1",
      }),
    ).toThrow(/EDGE_TRUST_PROXY no longer accepts a proxy hop count/);
  });

  // "auto" is the infra/azure sentinel for "the ACA ingress range", and
  // main.bicep resolves it before the container sees it. If one ever arrives the
  // deployment did not resolve it, which is worth saying plainly here rather than
  // letting proxy-addr fail on it as a malformed IP inside buildApp.
  it("refuses the infra sentinel EDGE_TRUST_PROXY=auto", () => {
    expect(() => loadConfig({ ...ENV, EDGE_TRUST_PROXY: "auto" })).toThrow(
      /EDGE_TRUST_PROXY does not accept "auto"/,
    );
  });

  // The gap a validator has to close, and the reason it cannot just call into
  // proxy-addr: these are values proxy-addr ACCEPTS and reinterprets. ipaddr.js
  // reads legacy short-form IPv4, so "10.0.2" compiles to the single host
  // 10.0.0.2 — it matches nothing the ingress presents, req.ip collapses to the
  // ingress address, and /health stays green. A malformed value proxy-addr
  // rejects was never the risk: that already throws inside `Fastify()`.
  it("refuses an address proxy-addr would silently reinterpret", () => {
    for (const raw of ["10.0.2", "1.2.3", "10.0", "010.0.2.0", "10.0.2.0/23,10.0.4"]) {
      expect(() => loadConfig({ ...ENV, EDGE_TRUST_PROXY: raw })).toThrow(
        /EDGE_TRUST_PROXY is not a trusted-proxy address list/,
      );
    }
    // The error names the offending part, not the whole list, so an operator
    // reading a deploy log sees which entry to fix.
    expect(() => loadConfig({ ...ENV, EDGE_TRUST_PROXY: "10.0.2.0/23,10.0.4" })).toThrow(
      /bad: "10\.0\.4"/,
    );
    // The dev-gateway shares the parse, so it fails closed identically.
    expect(() =>
      loadDevGatewayConfig({
        ...ENV,
        EDGE_DEV_DATABASE_URL: "postgresql://helix_dev:helix_dev@db:5432/helix",
        EDGE_TRUST_PROXY: "10.0.2",
      }),
    ).toThrow(/EDGE_TRUST_PROXY is not a trusted-proxy address list/);
  });

  // The one overlap where zod is LOOSER than proxy-addr: cidrv4/cidrv6 accept a
  // /0 prefix (even the non-canonical "10.0.2.0/0"), and Fastify() then throws
  // on it at construction — a boot crash, which under Container Apps' 'Single'
  // revision mode is a rollout that silently never takes. "0.0.0.0/0" is also
  // the natural spelling of "trust any proxy", so it will be written someday.
  // Refusing it at the parse is the same boot-time failure with an error that
  // names what to write instead.
  it("refuses a zero-prefix CIDR, which is 'trust any peer' by another spelling", () => {
    for (const raw of ["0.0.0.0/0", "::/0", "10.0.2.0/0", "10.0.2.0/24,0.0.0.0/0"]) {
      expect(() => loadConfig({ ...ENV, EDGE_TRUST_PROXY: raw })).toThrow(
        /EDGE_TRUST_PROXY is not a trusted-proxy address list/,
      );
    }
    // The advice names broad-but-still-peer-validating spellings — and not
    // "true": the infra template rejects it, so recommending it here would
    // point the operator at a deploy-time dead end.
    expect(() => loadConfig({ ...ENV, EDGE_TRUST_PROXY: "0.0.0.0/0" })).toThrow(/uniquelocal/);
    expect(() => loadConfig({ ...ENV, EDGE_TRUST_PROXY: "0.0.0.0/0" })).toThrow(/10\.0\.0\.0\/16/);
    expect(() => loadConfig({ ...ENV, EDGE_TRUST_PROXY: "0.0.0.0/0" })).not.toThrow(/"true"/);
    // The dev-gateway shares the parse, so it fails closed identically.
    expect(() =>
      loadDevGatewayConfig({
        ...ENV,
        EDGE_DEV_DATABASE_URL: "postgresql://helix_dev:helix_dev@db:5432/helix",
        EDGE_TRUST_PROXY: "::/0",
      }),
    ).toThrow(/EDGE_TRUST_PROXY is not a trusted-proxy address list/);
  });

  // The dotted-netmask CIDR is the reverse overlap: proxy-addr reads it exactly
  // as written ("10.0.2.0/255.255.254.0" compiles and covers the same /23), but
  // the grammar here is deliberately a strict subset, so this is a named
  // narrowing, not an oversight — and the error says how to convert it.
  it("refuses the dotted-netmask CIDR form, naming the prefix-length spelling", () => {
    expect(() => loadConfig({ ...ENV, EDGE_TRUST_PROXY: "10.0.2.0/255.255.254.0" })).toThrow(
      /EDGE_TRUST_PROXY is not a trusted-proxy address list/,
    );
    expect(() => loadConfig({ ...ENV, EDGE_TRUST_PROXY: "10.0.2.0/255.255.254.0" })).toThrow(
      /"10\.0\.2\.0\/255\.255\.254\.0" is "10\.0\.2\.0\/23"/,
    );
  });

  it("accepts the address forms of EDGE_TRUST_PROXY, and defaults to trusting nothing", () => {
    // Unset/blank → the socket peer is the client (opt-in, not defaulted on).
    // Blank is load-bearing: infra/azure spells "the subnet" as 'auto', so an
    // operator who deliberately blanks edgeTrustProxy still gets trust nothing.
    expect(loadConfig({ ...ENV }).trustProxy).toBe(false);
    expect(loadConfig({ ...ENV, EDGE_TRUST_PROXY: "" }).trustProxy).toBe(false);
    // Whitespace-only counts as unset, the same rule requirePositiveMs applies
    // to every other env duration — compose and CI pass blank strings for vars
    // that are declared but not set.
    expect(loadConfig({ ...ENV, EDGE_TRUST_PROXY: "   " }).trustProxy).toBe(false);
    expect(loadConfig({ ...ENV, EDGE_TRUST_PROXY: "false" }).trustProxy).toBe(false);
    expect(loadConfig({ ...ENV, EDGE_TRUST_PROXY: "true" }).trustProxy).toBe(true);
    // `0` is the one count that is not refused: fastify branched on
    // `if (trustProxy)`, so it was falsy and meant trust nothing — the same as
    // unset. It keeps that meaning rather than failing the boot for no gain.
    expect(loadConfig({ ...ENV, EDGE_TRUST_PROXY: "0" }).trustProxy).toBe(false);
    expect(loadConfig({ ...ENV, EDGE_TRUST_PROXY: " 00 " }).trustProxy).toBe(false);
    // A CIDR (what infra/azure passes: the ACA ingress range), a list,
    // and a proxy-addr preset all pass through verbatim for Fastify to compile.
    expect(loadConfig({ ...ENV, EDGE_TRUST_PROXY: "10.0.2.0/23" }).trustProxy).toBe("10.0.2.0/23");
    expect(loadConfig({ ...ENV, EDGE_TRUST_PROXY: "10.0.2.0/23,10.0.4.0/23" }).trustProxy).toBe(
      "10.0.2.0/23,10.0.4.0/23",
    );
    expect(loadConfig({ ...ENV, EDGE_TRUST_PROXY: "uniquelocal" }).trustProxy).toBe("uniquelocal");
  });

  // The value is only worth anything if Fastify derives the req.ip we expect
  // from it, so drive the parsed config through the option the way app.ts does.
  // `app.inject` presents a loopback socket peer, which is what distinguishes a
  // trusted ingress from an untrusted direct caller here.
  describe("the parsed value drives req.ip as intended", () => {
    const ipFrom = async (trustProxyEnv: string | undefined, xff: string, peer?: string) => {
      const { trustProxy } = loadConfig(
        trustProxyEnv === undefined ? { ...ENV } : { ...ENV, EDGE_TRUST_PROXY: trustProxyEnv },
      );
      const app = Fastify({ trustProxy });
      app.get("/", (req) => ({ ip: req.ip }));
      const res = await app.inject({
        method: "GET",
        url: "/",
        headers: { "x-forwarded-for": xff },
        ...(peer ? { remoteAddress: peer } : {}),
      });
      await app.close();
      return res.json<{ ip: string }>().ip;
    };

    it("ignores X-Forwarded-For from an untrusted peer", async () => {
      // Default (trust nothing) and a CIDR that does not cover the loopback peer
      // both refuse to believe the header — this is the anti-spoofing property.
      expect(await ipFrom(undefined, "203.0.113.7")).toBe("127.0.0.1");
      expect(await ipFrom("10.0.2.0/23", "203.0.113.7")).toBe("127.0.0.1");
    });

    it("resolves the real client through a trusted proxy address", async () => {
      // A CIDR naming the peer is what the deployed edge gets (the ACA ingress
      // range); loopback stands in for it under inject.
      expect(await ipFrom("127.0.0.0/8", "203.0.113.7")).toBe("203.0.113.7");
      expect(await ipFrom("loopback", "203.0.113.7")).toBe("203.0.113.7");
      // Chained proxies: the walk stops at the first address the list doesn't
      // cover, so an app-supplied prefix can't push a spoofed value through.
      expect(await ipFrom("127.0.0.0/8", "203.0.113.7, 198.51.100.9")).toBe("198.51.100.9");
    });

    // The pin that keeps the validator honest against the parser it guards.
    // `parseTrustProxy` is deliberately a second, stricter grammar than
    // proxy-addr's, so the two can drift: too strict and a workable value fails
    // the boot, too loose and the silent case returns. Assert the property that
    // matters instead of the grammar — a value we accept trusts the range as
    // WRITTEN, using a real ACA-shaped peer rather than inject's loopback.
    it("trusts the range as written, for every form the parse accepts", async () => {
      // Inside the written subnet → the header is believed.
      expect(await ipFrom("10.0.2.0/23", "203.0.113.7", "10.0.2.5")).toBe("203.0.113.7");
      expect(await ipFrom("uniquelocal", "203.0.113.7", "10.0.2.5")).toBe("203.0.113.7");
      expect(await ipFrom("10.0.2.4", "203.0.113.7", "10.0.2.4")).toBe("203.0.113.7");
      // Outside it → not believed, even though the peer is private.
      expect(await ipFrom("10.0.2.0/23", "203.0.113.7", "10.0.9.5")).toBe("10.0.9.5");
      // ACA presents the peer as an IPv4-mapped v6 address; the v4 CIDR must
      // still match it, or every client collapses into one bucket.
      expect(await ipFrom("10.0.2.0/23", "203.0.113.7", "::ffff:10.0.2.5")).toBe("203.0.113.7");
    });

    // The live defect, as a test (measured 2026-09-03; ADR-0011's 2026-09
    // amendment). ACA's ingress pods are addressed out of the platform-reserved
    // RFC 6598 ranges (100.100.x.x), not out of the apps subnet the container
    // runs in — so the shipped `auto` default named a network the peer was never
    // in, and every client bucketed per Envoy pod with /health green. This is a
    // property of the value infra/azure resolves, so it belongs next to the
    // parse rather than in the bicep.
    it("resolves the client from an ACA ingress peer, and not from the apps subnet", async () => {
      // What ships today: the ingress peer is inside the RFC 6598 block.
      expect(await ipFrom("100.64.0.0/10", "203.0.113.7", "100.100.1.0")).toBe("203.0.113.7");
      expect(await ipFrom("100.64.0.0/10", "203.0.113.7", "100.100.0.147")).toBe("203.0.113.7");
      // What shipped before, reproduced: a well-formed apps-subnet CIDR that the
      // peer is not in trusts nothing, and req.ip becomes the Envoy pod — one
      // bucket per pod, which is exactly what was read back out of rate_counters.
      expect(await ipFrom("10.0.2.0/23", "203.0.113.7", "100.100.1.0")).toBe("100.100.1.0");
      // And the two values the old advice reached for, which change nothing:
      // neither the VNet prefix nor `uniquelocal` (10/8 + 172.16/12 + 192.168/16
      // + fc00::/7) contains 100.100.x.x.
      expect(await ipFrom("uniquelocal", "203.0.113.7", "100.100.1.0")).toBe("100.100.1.0");
      expect(await ipFrom("10.0.0.0/16", "203.0.113.7", "100.100.1.0")).toBe("100.100.1.0");
    });

    // ...and the concrete failure the validator exists to prevent: were "10.0.2"
    // to reach Fastify it would compile without complaint and resolve req.ip to
    // the ingress, which is why loadConfig refuses it above rather than here.
    it("would silently collapse req.ip on a dropped octet, hence the refusal", async () => {
      const app = Fastify({ trustProxy: "10.0.2" });
      app.get("/", (req) => ({ ip: req.ip }));
      const res = await app.inject({
        method: "GET",
        url: "/",
        headers: { "x-forwarded-for": "203.0.113.7" },
        remoteAddress: "10.0.2.5",
      });
      await app.close();
      expect(res.json<{ ip: string }>().ip).toBe("10.0.2.5");
    });

    // ...and the one value zod passes that Fastify cannot compile at all: a /0
    // throws inside Fastify() at construction, with proxy-addr's own cryptic
    // "invalid range" error. Pinned so the refusal in the parse suite above is
    // visibly pre-empting a real crash, not a hypothetical one.
    it("would throw inside Fastify() on a zero prefix, hence the refusal", () => {
      expect(() => Fastify({ trustProxy: "0.0.0.0/0" })).toThrow(/invalid range/);
    });
  });

  it("throws a clear error on missing requirements", () => {
    expect(() => loadConfig({})).toThrow(/DATABASE_URL/);
    expect(() => loadConfig({ DATABASE_URL: "x" })).toThrow(/AZURE_STORAGE_CONNECTION_STRING/);
  });

  it("refuses the dev bypass in production", () => {
    expect(() =>
      loadConfig({ ...ENV, EDGE_DEV_ALLOW_UNAUTHENTICATED: "true", NODE_ENV: "production" }),
    ).toThrow(/refused in production/);
  });

  it("refuses the owner-DSN fallback in production (role-split, ADR-0002)", () => {
    // Only DATABASE_URL (the schema owner) set in prod → boot-fail rather than
    // silently connect as owner and bypass RLS.
    const { EDGE_DATABASE_URL: _omit, ...ownerOnly } = ENV;
    void _omit;
    expect(() => loadConfig({ ...ownerOnly, ...MI_BLOB_ENV, NODE_ENV: "production" })).toThrow(
      /EDGE_DATABASE_URL.*required in production/,
    );
    // With the least-privilege role DSN present, prod boots and uses it.
    const config = loadConfig({ ...ENV, ...MI_BLOB_ENV, NODE_ENV: "production" });
    expect(config.databaseUrl).toBe(ENV.EDGE_DATABASE_URL);
  });

  it("still allows the owner-DSN fallback outside production", () => {
    const { EDGE_DATABASE_URL: _omit, ...ownerOnly } = ENV;
    void _omit;
    const config = loadConfig(ownerOnly);
    expect(config.databaseUrl).toBe(ENV.DATABASE_URL);
  });

  const noTls = {
    DATABASE_URL: ENV.DATABASE_URL,
    AZURE_STORAGE_CONNECTION_STRING: ENV.AZURE_STORAGE_CONNECTION_STRING,
  };

  it("requires TLS outside production (HTTPS-only platform)", () => {
    expect(() => loadConfig(noTls)).toThrow(/TLS is required/);
    // Production opts out: ingress owns the cert, the edge runs HTTP behind it.
    // Prod also uses managed-identity blob auth (the connection string is refused).
    const prod = loadConfig({
      DATABASE_URL: ENV.DATABASE_URL,
      EDGE_DATABASE_URL: ENV.EDGE_DATABASE_URL,
      ...MI_BLOB_ENV,
      NODE_ENV: "production",
    });
    expect(prod.tls).toBeNull();
    expect(prod.publicScheme).toBe("https");
  });

  it("selects managed-identity blob auth from endpoint + client_id", () => {
    const config = loadConfig({
      DATABASE_URL: ENV.DATABASE_URL,
      EDGE_DATABASE_URL: ENV.EDGE_DATABASE_URL,
      ...MI_BLOB_ENV,
      NODE_ENV: "production",
    });
    expect(config.blob.provider).toBe("azure");
    expect(config.blob.endpoint).toBe("https://prodacct.blob.core.windows.net");
    expect(config.blob.auth.mode).toBe("managed-identity");
    // Regression (issue #15): the MI path carries no account key, structurally.
    expect("accountKey" in config.blob.auth).toBe(false);
    if (config.blob.auth.mode === "managed-identity") {
      expect(config.blob.auth.clientId).toBe(MI_BLOB_ENV.AZURE_CLIENT_ID);
      expect(config.blob.auth.identityEndpoint).toBe(MI_BLOB_ENV.IDENTITY_ENDPOINT);
      expect(config.blob.auth.identityHeader).toBe(MI_BLOB_ENV.IDENTITY_HEADER);
    }
  });

  it("uses shared-key blob auth from a connection string in dev", () => {
    const config = loadConfig({ ...ENV });
    expect(config.blob.auth.mode).toBe("shared-key");
    if (config.blob.auth.mode === "shared-key") {
      expect(config.blob.auth.accountName).toBe("devstoreaccount1");
      expect(config.blob.auth.accountKey).toEqual(Buffer.from(AZURITE_KEY, "base64"));
    }
  });

  it("prefers managed identity over a connection string when both are set", () => {
    const config = loadConfig({ ...ENV, ...MI_BLOB_ENV, NODE_ENV: "production" });
    expect(config.blob.auth.mode).toBe("managed-identity");
  });

  it("refuses the account-key (SharedKey) blob path in production", () => {
    expect(() => loadConfig({ ...ENV, NODE_ENV: "production" })).toThrow(/refused in production/);
  });

  it("requires IDENTITY_ENDPOINT/IDENTITY_HEADER for managed-identity blob auth", () => {
    const partial = {
      AZURE_STORAGE_BLOB_ENDPOINT: MI_BLOB_ENV.AZURE_STORAGE_BLOB_ENDPOINT,
      AZURE_CLIENT_ID: MI_BLOB_ENV.AZURE_CLIENT_ID,
    };
    expect(() => loadConfig({ ...ENV, ...partial })).toThrow(
      /IDENTITY_ENDPOINT and IDENTITY_HEADER/,
    );
  });

  it("throws when no blob auth is configured at all", () => {
    expect(() =>
      loadConfig({
        DATABASE_URL: ENV.DATABASE_URL,
        EDGE_DATABASE_URL: ENV.EDGE_DATABASE_URL,
        NODE_ENV: "production",
      }),
    ).toThrow(/AZURE_STORAGE_CONNECTION_STRING/);
  });

  it("requires TLS cert and key together", () => {
    expect(() => loadConfig({ ...noTls, EDGE_TLS_CERT_FILE: "/c.pem" })).toThrow(/together/);
  });
});

describe("auth config", () => {
  const ENV = {
    DATABASE_URL: "postgresql://helix:helix@db:5432/helix",
    EDGE_DATABASE_URL: "postgresql://helix_edge:helix_edge@db:5432/helix",
    AZURE_STORAGE_CONNECTION_STRING: AZURITE_CS,
    EDGE_TLS_CERT_FILE: "/certs/local-helix.pem",
    EDGE_TLS_KEY_FILE: "/certs/local-helix-key.pem",
  };
  // 32 zero bytes, base64.
  const SECRET = Buffer.alloc(32).toString("base64");
  const AUTH_ENV = {
    EDGE_OIDC_ISSUER: "https://idp.example.com",
    EDGE_OIDC_CLIENT_ID: "helix-edge",
    EDGE_OIDC_CLIENT_SECRET: "s3cret",
    EDGE_AUTH_SECRET: SECRET,
  };

  it("is null when no auth env is present (fail-closed boot)", () => {
    expect(loadConfig({ ...ENV }).auth).toBeNull();
  });

  it("rejects a partial auth block", () => {
    expect(() => loadConfig({ ...ENV, EDGE_OIDC_ISSUER: "https://idp.example.com" })).toThrow(
      /Partial auth config/,
    );
  });

  it("parses a full auth block with defaults", () => {
    const auth = loadConfig({ ...ENV, ...AUTH_ENV }).auth;
    expect(auth).not.toBeNull();
    expect(auth?.issuerUrl).toBe("https://idp.example.com");
    expect(auth?.groupsClaim).toBe("groups");
    expect(auth?.principalClaim).toBe("oid");
    expect(auth?.scopes).toBe("openid profile email groups");
    expect(auth?.secret).toEqual(Buffer.alloc(32));
    expect(auth?.sessionTtlMs).toBe(8 * 60 * 60 * 1000);
    expect(auth?.refreshAfterMs).toBe(60 * 60 * 1000);
    expect(auth?.handoffTtlSec).toBe(30);
  });

  // ADR-0048 decision 2, as amended: the principal-claim NAME is a seam (most
  // non-Entra issuers' stable id is their own `sub` — pairwise `sub` is
  // Entra's deviation, not the OIDC norm), and the one dangerous value is
  // gated so the pairwise bug cannot return through a typo.
  describe("EDGE_OIDC_PRINCIPAL_CLAIM (the non-Entra seam)", () => {
    it("accepts a custom claim name", () => {
      const auth = loadConfig({ ...ENV, ...AUTH_ENV, EDGE_OIDC_PRINCIPAL_CLAIM: "uid" }).auth;
      expect(auth?.principalClaim).toBe("uid");
    });

    it("refuses sub by default — Entra's sub is pairwise per client id", () => {
      expect(() => loadConfig({ ...ENV, ...AUTH_ENV, EDGE_OIDC_PRINCIPAL_CLAIM: "sub" })).toThrow(
        /pairwise/,
      );
    });

    it("accepts sub behind the explicit allow flag (the operator asserts a stable sub)", () => {
      const auth = loadConfig({
        ...ENV,
        ...AUTH_ENV,
        EDGE_OIDC_PRINCIPAL_CLAIM: "sub",
        EDGE_OIDC_ALLOW_SUB_PRINCIPAL: "true",
      }).auth;
      expect(auth?.principalClaim).toBe("sub");
    });

    it.each([
      ["empty", ""],
      ["whitespace", "o id"],
      ["oversized", "c".repeat(65)],
      ["garbage", "oid;drop"],
    ])("refuses a malformed claim name (%s)", (_label, value) => {
      expect(() => loadConfig({ ...ENV, ...AUTH_ENV, EDGE_OIDC_PRINCIPAL_CLAIM: value })).toThrow(
        /EDGE_OIDC_PRINCIPAL_CLAIM/,
      );
    });
  });

  it("rejects an http issuer unless explicitly allowed", () => {
    const httpIssuer = { ...ENV, ...AUTH_ENV, EDGE_OIDC_ISSUER: "http://localhost:3002" };
    expect(() => loadConfig(httpIssuer)).toThrow(/must be https/);
    const allowed = loadConfig({ ...httpIssuer, EDGE_OIDC_ALLOW_INSECURE: "true" });
    expect(allowed.auth?.allowInsecureIdp).toBe(true);
  });

  it("rejects a short secret", () => {
    expect(() =>
      loadConfig({ ...ENV, ...AUTH_ENV, EDGE_AUTH_SECRET: Buffer.alloc(16).toString("base64") }),
    ).toThrow(/32 bytes/);
  });

  it("parses a full auth block as a secret credential", () => {
    const auth = loadConfig({ ...ENV, ...AUTH_ENV }).auth;
    expect(auth?.credential).toEqual({ kind: "secret", clientSecret: "s3cret" });
  });

  // Certificate auth (private_key_jwt) for tenants that block client secrets.
  const PEM_KEY = "-----BEGIN PRIVATE KEY-----\nMIG\n-----END PRIVATE KEY-----";
  const PEM_CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
  const CERT_BASE = {
    EDGE_OIDC_ISSUER: "https://idp.example.com",
    EDGE_OIDC_CLIENT_ID: "helix-edge",
    EDGE_AUTH_SECRET: SECRET,
  };

  it("parses a certificate credential (raw PEM)", () => {
    const auth = loadConfig({
      ...ENV,
      ...CERT_BASE,
      EDGE_OIDC_CLIENT_PRIVATE_KEY: PEM_KEY,
      EDGE_OIDC_CLIENT_CERTIFICATE: PEM_CERT,
    }).auth;
    expect(auth?.credential).toEqual({
      kind: "certificate",
      privateKeyPem: PEM_KEY,
      certificatePem: PEM_CERT,
    });
  });

  it("accepts base64-encoded PEM for certificate credentials", () => {
    const auth = loadConfig({
      ...ENV,
      ...CERT_BASE,
      EDGE_OIDC_CLIENT_PRIVATE_KEY: Buffer.from(PEM_KEY).toString("base64"),
      EDGE_OIDC_CLIENT_CERTIFICATE: Buffer.from(PEM_CERT).toString("base64"),
    }).auth;
    expect(auth?.credential).toEqual({
      kind: "certificate",
      privateKeyPem: PEM_KEY,
      certificatePem: PEM_CERT,
    });
  });

  it("rejects a non-PEM, non-base64 certificate value", () => {
    expect(() =>
      loadConfig({
        ...ENV,
        ...CERT_BASE,
        EDGE_OIDC_CLIENT_PRIVATE_KEY: "not-a-pem",
        EDGE_OIDC_CLIENT_CERTIFICATE: PEM_CERT,
      }),
    ).toThrow(/PEM or base64-encoded PEM/);
  });

  it("rejects a certificate credential missing its private key", () => {
    expect(() =>
      loadConfig({ ...ENV, ...CERT_BASE, EDGE_OIDC_CLIENT_CERTIFICATE: PEM_CERT }),
    ).toThrow(/needs both/);
  });

  it("rejects both a secret and a certificate", () => {
    expect(() =>
      loadConfig({
        ...ENV,
        ...AUTH_ENV,
        EDGE_OIDC_CLIENT_PRIVATE_KEY: PEM_KEY,
        EDGE_OIDC_CLIENT_CERTIFICATE: PEM_CERT,
      }),
    ).toThrow(/not both/);
  });

  it("rejects a base block with no credential at all", () => {
    expect(() => loadConfig({ ...ENV, ...CERT_BASE })).toThrow(/needs a client credential/);
  });
});

describe("publicOrigin", () => {
  const ENV = {
    DATABASE_URL: "postgresql://helix:helix@db:5432/helix",
    EDGE_DATABASE_URL: "postgresql://helix_edge:helix_edge@db:5432/helix",
    AZURE_STORAGE_CONNECTION_STRING: AZURITE_CS,
    EDGE_TLS_CERT_FILE: "/certs/local-helix.pem",
    EDGE_TLS_KEY_FILE: "/certs/local-helix-key.pem",
  };

  it("builds https host URLs from config, omitting the default 443", () => {
    const dev = loadConfig({ ...ENV, EDGE_PUBLIC_PORT: "8080" });
    expect(controlOrigin(dev, "auth")).toBe("https://auth.local.helix.azxlabs.io:8080");
    expect(publicOrigin(dev, "demo")).toBe("https://demo.local.helix.azxlabs.io:8080");

    // Production: ingress terminates TLS (no edge cert), public port 443, and
    // blob auth is managed identity (the connection string is refused in prod).
    const prod = loadConfig({
      DATABASE_URL: ENV.DATABASE_URL,
      EDGE_DATABASE_URL: ENV.EDGE_DATABASE_URL,
      ...MI_BLOB_ENV,
      EDGE_BASE_DOMAIN: "azx.helix.azxlabs.io",
      EDGE_PUBLIC_PORT: "443",
      NODE_ENV: "production",
    });
    expect(controlOrigin(prod, "auth")).toBe("https://auth.azx.helix.azxlabs.io");
    expect(publicOrigin(prod, null)).toBe("https://azx.helix.azxlabs.io");
  });

  it("refuses reserved control labels", () => {
    const dev = loadConfig({ ...ENV, EDGE_PUBLIC_PORT: "8080" });
    for (const label of RESERVED_SUBDOMAINS) {
      expect(() => publicOrigin(dev, label)).toThrow(/controlOrigin/);
    }
    const split = loadConfig({
      ...ENV,
      EDGE_PUBLIC_PORT: "8080",
      EDGE_BASE_DOMAIN: "helix-apps.localhost",
      EDGE_CONTROL_DOMAIN: "local.helix.azxlabs.io",
    });
    for (const label of RESERVED_SUBDOMAINS) {
      expect(() => publicOrigin(split, label)).toThrow(/controlOrigin/);
    }
  });
});

describe("resolveControlDomain / EDGE_CONTROL_DOMAIN boot validation", () => {
  const ENV = {
    DATABASE_URL: "postgresql://helix:helix@db:5432/helix",
    EDGE_DATABASE_URL: "postgresql://helix_edge:helix_edge@db:5432/helix",
    AZURE_STORAGE_CONNECTION_STRING: AZURITE_CS,
    EDGE_TLS_CERT_FILE: "/certs/local-helix.pem",
    EDGE_TLS_KEY_FILE: "/certs/local-helix-key.pem",
    EDGE_DEV_DATABASE_URL: "postgresql://helix_dev:helix_dev@db:5432/helix",
  };
  const base = "local.helix.azxlabs.io";

  it("unset, blank, or equal to base keeps legacy single-domain mode", () => {
    for (const control of [undefined, "", "  ", base, base.toUpperCase()]) {
      const cfg = loadConfig({
        ...ENV,
        ...(control !== undefined ? { EDGE_CONTROL_DOMAIN: control } : {}),
      });
      expect(cfg.controlDomain).toBe(base);
      expect(cfg.baseDomain).toBe(base);
    }
  });

  it("rejects a control subdomain of the apps domain", () => {
    expect(() => loadConfig({ ...ENV, EDGE_CONTROL_DOMAIN: `ctl.${base}` })).toThrow(
      /subdomain of EDGE_BASE_DOMAIN/,
    );
    expect(() => loadDevGatewayConfig({ ...ENV, EDGE_CONTROL_DOMAIN: `ctl.${base}` })).toThrow(
      /subdomain of EDGE_BASE_DOMAIN/,
    );
  });

  it.each([
    ["http://x.test", /valid hostname/],
    ["x.test:8443", /valid hostname/],
    ["x", /valid hostname/],
    [".x.test", /valid hostname/],
    ["x_y.test", /valid hostname/],
  ])("rejects malformed control domain %s", (control, pattern) => {
    expect(() => loadConfig({ ...ENV, EDGE_CONTROL_DOMAIN: control })).toThrow(pattern);
    expect(() => loadDevGatewayConfig({ ...ENV, EDGE_CONTROL_DOMAIN: control })).toThrow(pattern);
  });

  it("allows control parent of apps and lowercases input", () => {
    const cfg = loadConfig({
      ...ENV,
      EDGE_BASE_DOMAIN: "apps.helix.customer.test",
      EDGE_CONTROL_DOMAIN: "HELIX.CUSTOMER.TEST",
    });
    expect(cfg.controlDomain).toBe("helix.customer.test");
    expect(classifyHost("auth.helix.customer.test", cfg.baseDomain, cfg.controlDomain)).toEqual({
      kind: "auth",
    });
  });

  it("rejects an apps domain on a reserved control label", () => {
    const control = "example.test";
    for (const base of [`auth.${control}`, `tenant.auth.${control}`, `portal.${control}`]) {
      expect(() =>
        loadConfig({ ...ENV, EDGE_BASE_DOMAIN: base, EDGE_CONTROL_DOMAIN: control }),
      ).toThrow(/EDGE_BASE_DOMAIN/);
      expect(() =>
        loadDevGatewayConfig({ ...ENV, EDGE_BASE_DOMAIN: base, EDGE_CONTROL_DOMAIN: control }),
      ).toThrow(/EDGE_BASE_DOMAIN/);
    }
  });
});

describe("LLM upstream config (ADR-0046)", () => {
  const ENV = {
    DATABASE_URL: "postgresql://helix:helix@db:5432/helix",
    EDGE_DATABASE_URL: "postgresql://helix_edge:helix_edge@db:5432/helix",
    AZURE_STORAGE_CONNECTION_STRING: AZURITE_CS,
    EDGE_TLS_CERT_FILE: "/certs/local-helix.pem",
    EDGE_TLS_KEY_FILE: "/certs/local-helix-key.pem",
  };

  it("defaults both paths to the first-party shapes", () => {
    const config = loadConfig({ ...ENV });
    expect(config.llm.path).toBe("/v1/messages");
    expect(config.llm.openai.path).toBe("/v1/chat/completions");
  });

  it("takes the Foundry shape from env — endpoint stays an origin, the path carries the prefix", () => {
    const config = loadConfig({
      ...ENV,
      EDGE_LLM_ENDPOINT: "https://contoso.services.ai.azure.com",
      EDGE_LLM_ANTHROPIC_PATH: "/anthropic/v1/messages",
      EDGE_LLM_ANTHROPIC_CONNECTION: "foundry",
      EDGE_LLM_OPENAI_ENDPOINT: "https://contoso.services.ai.azure.com",
      EDGE_LLM_OPENAI_PATH: "/openai/v1/chat/completions",
      EDGE_LLM_OPENAI_CONNECTION: "foundry-openai",
    });
    expect(config.llm.endpoint).toBe("https://contoso.services.ai.azure.com");
    expect(config.llm.path).toBe("/anthropic/v1/messages");
    expect(config.llm.connection).toBe("foundry");
    expect(config.llm.openai.path).toBe("/openai/v1/chat/completions");
    expect(config.llm.openai.connection).toBe("foundry-openai");
  });

  it.each([
    ["EDGE_LLM_ANTHROPIC_PATH", "anthropic/v1/messages", "no leading slash"],
    ["EDGE_LLM_OPENAI_PATH", "/openai/v1/chat/completions?api-version=1", "a query"],
    ["EDGE_LLM_OPENAI_PATH", "/openai/v1/chat/completions#x", "a fragment"],
    // URL normalisation would rewrite these, so they could never equal the
    // path claim egress binds — refused at boot, not per-call at egress.
    ["EDGE_LLM_ANTHROPIC_PATH", "/anthropic/../v1/messages", "a dot segment"],
    ["EDGE_LLM_ANTHROPIC_PATH", "/v1 messages", "a space (would percent-encode)"],
    [
      "EDGE_LLM_OPENAI_PATH",
      "//evil.example/x",
      "protocol-relative (never an origin escape — the target is string-concat — but refused for clarity)",
    ],
  ])("refuses %s=%s (%s) — it would die silently at the egress path check", (key, value) => {
    expect(() => loadConfig({ ...ENV, [key]: value })).toThrow(new RegExp(`${key}.*bare path`));
  });
});

describe("the edge↔portal internal-JWT key (HELIX_INTERNAL_SECRET)", () => {
  const ENV = {
    DATABASE_URL: "postgresql://helix:helix@db:5432/helix",
    EDGE_DATABASE_URL: "postgresql://helix_edge:helix_edge@db:5432/helix",
    AZURE_STORAGE_CONNECTION_STRING: AZURITE_CS,
    EDGE_TLS_CERT_FILE: "/certs/local-helix.pem",
    EDGE_TLS_KEY_FILE: "/certs/local-helix-key.pem",
  };

  it("is null when unset — the mint side gates, it does not boot-fail", () => {
    expect(loadConfig({ ...ENV }).internalSecret).toBeNull();
    // The dev-gateway shares the parse and the optional treatment.
    expect(
      loadDevGatewayConfig({ ...ENV, EDGE_DEV_DATABASE_URL: "postgresql://helix_dev@db/helix" })
        .internalSecret,
    ).toBeNull();
  });

  it("parses the secret when set", () => {
    const config = loadConfig({
      ...ENV,
      HELIX_INTERNAL_SECRET: "0123456789abcdef0123456789abcdef",
    });
    expect(config.internalSecret).toEqual(Buffer.from("0123456789abcdef0123456789abcdef"));
  });

  it("refuses a too-short secret (would weaken the derived key)", () => {
    expect(() => loadConfig({ ...ENV, HELIX_INTERNAL_SECRET: "short" })).toThrow(
      /HELIX_INTERNAL_SECRET must be at least 32 bytes/,
    );
  });
});

describe("loadDevGatewayConfig", () => {
  // The dev-gateway's ONLY required env is its own helix_dev DSN (+ TLS in dev).
  const DEV_ENV = {
    EDGE_DEV_DATABASE_URL: "postgresql://helix_dev:helix_dev@db:5432/helix",
    EDGE_TLS_CERT_FILE: "/certs/local-helix.pem",
    EDGE_TLS_KEY_FILE: "/certs/local-helix-key.pem",
  };

  it("loads from the dev DSN alone — no edge DSN or blob env required", () => {
    // Deliberately NO EDGE_DATABASE_URL, DATABASE_URL, or AZURE_STORAGE_* here.
    const config = loadDevGatewayConfig({ ...DEV_ENV });
    expect(config.devGateway.databaseUrl).toBe(DEV_ENV.EDGE_DEV_DATABASE_URL);
    expect(config.devGateway.allowDevMode).toBe(false); // opt-in, default off
    expect(config.devGateway.port).toBe(8082);
    // Shared gateway defaults still resolve.
    expect(config.baseDomain).toBe("local.helix.azxlabs.io");
    expect(config.llm.connection).toBe("anthropic");
    expect(config.fetch.egressUrl).toBeNull();
    // Airtight: the type — and the value — structurally lack the edge data plane,
    // so this process cannot name the helix_edge pool or a blob account.
    expect("databaseUrl" in config).toBe(false);
    expect("blob" in config).toBe(false);
    expect("auth" in config).toBe(false);
  });

  it("reflects the opt-in flag and port overrides", () => {
    const config = loadDevGatewayConfig({
      ...DEV_ENV,
      EDGE_ALLOW_DEV_MODE: "true",
      EDGE_DEV_GATEWAY_PORT: "9099",
    });
    expect(config.devGateway.allowDevMode).toBe(true);
    expect(config.devGateway.port).toBe(9099);
  });

  it("requires EDGE_DEV_DATABASE_URL with NO owner-DSN fallback", () => {
    // Even a full set of edge/owner DSNs must not satisfy the dev-gateway — the
    // env-literal RLS only holds when it connects as helix_dev (dev-mode §5.3).
    expect(() =>
      loadDevGatewayConfig({
        DATABASE_URL: "postgresql://helix@db/helix",
        EDGE_DATABASE_URL: "postgresql://helix_edge@db/helix",
        EDGE_TLS_CERT_FILE: "/c.pem",
        EDGE_TLS_KEY_FILE: "/k.pem",
      }),
    ).toThrow(/EDGE_DEV_DATABASE_URL/);
  });

  it("enforces the HTTPS-only TLS rule outside production", () => {
    const noTls = { EDGE_DEV_DATABASE_URL: DEV_ENV.EDGE_DEV_DATABASE_URL };
    expect(() => loadDevGatewayConfig(noTls)).toThrow(/TLS is required/);
  });

  it("runs without a local cert in production (ingress terminates TLS)", () => {
    const config = loadDevGatewayConfig({
      EDGE_DEV_DATABASE_URL: DEV_ENV.EDGE_DEV_DATABASE_URL,
      NODE_ENV: "production",
    });
    expect(config.tls).toBeNull();
    expect(config.devGateway.databaseUrl).toBe(DEV_ENV.EDGE_DEV_DATABASE_URL);
  });
});
