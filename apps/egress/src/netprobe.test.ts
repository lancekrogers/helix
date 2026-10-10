import { EventEmitter } from "node:events";
import { createServer } from "node:net";
import { describe, expect, it, vi } from "vitest";
import * as netprobe from "./netprobe.js";
import {
  buildChecks,
  classify,
  parseConfig,
  probeTcp,
  probeTls,
  runChecks,
  type CheckSpec,
  type ProbeConfig,
} from "./netprobe.js";

function sampleConfig(overrides: Partial<ProbeConfig> = {}): ProbeConfig {
  return {
    nsg: "enforce",
    firewall: true,
    fqdnAllowlist: false,
    fqdnProtocol: "tls",
    appsIp: "10.0.2.10",
    kvPlatformIp: "10.0.7.4",
    blobIp: "10.0.7.5",
    kvConnectionsIp: "10.0.7.6",
    kvDelegatedIp: "10.0.7.7",
    postgresHost: "postgres.example.internal",
    allowedHost: "mcr.microsoft.com",
    canaryHost: "probe-canary.example.com",
    timeoutMs: 5000,
    ...overrides,
  };
}

function sampleEnv(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    PROBE_EXPECT_NSG: "enforce",
    PROBE_EXPECT_FIREWALL: "true",
    PROBE_EXPECT_FQDN_ALLOWLIST: "false",
    PROBE_APPS_IP: "10.0.2.10",
    PROBE_KV_PLATFORM_IP: "10.0.7.4",
    PROBE_BLOB_PE_IP: "10.0.7.5",
    PROBE_KV_CONNECTIONS_IP: "10.0.7.6",
    PROBE_KV_DELEGATED_IP: "10.0.7.7",
    PROBE_POSTGRES_HOST: "postgres.example.internal",
    PROBE_ALLOWED_HOST: "mcr.microsoft.com",
    PROBE_CANARY_HOST: "probe-canary.example.com",
    ...overrides,
  };
}

describe("classify", () => {
  it.each([
    { error: undefined, timedOut: true, want: "blocked" as const },
    { error: { code: "ETIMEDOUT" }, timedOut: false, want: "blocked" as const },
    { error: { code: "ECONNREFUSED" }, timedOut: false, want: "reachable" as const },
    { error: { code: "ECONNRESET" }, timedOut: false, want: "reachable" as const },
    { error: { code: "ENOTFOUND" }, timedOut: false, want: "unresolved" as const },
    { error: { code: "EAI_AGAIN" }, timedOut: false, want: "unresolved" as const },
    { error: { code: "EHOSTUNREACH" }, timedOut: false, want: "error" as const },
    { error: undefined, timedOut: false, want: "reachable" as const },
  ])("$want for error=$error timedOut=$timedOut", ({ error, timedOut, want }) => {
    expect(classify(error as NodeJS.ErrnoException | undefined, timedOut)).toBe(want);
  });
});

describe("probeTcp", () => {
  it("reports reachable when a local server accepts", async () => {
    const server = createServer((socket) => {
      socket.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const port = (server.address() as { port: number }).port;
    const outcome = await probeTcp("127.0.0.1", port, 2000);
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
    expect(outcome).toBe("reachable");
  });

  it("reports reachable on connection refused", async () => {
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const port = (server.address() as { port: number }).port;
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
    const outcome = await probeTcp("127.0.0.1", port, 2000);
    expect(outcome).toBe("reachable");
  });

  it("reports blocked when the connect hangs until timeout", async () => {
    const hanging = new EventEmitter() as ReturnType<typeof import("node:net").connect>;
    hanging.destroy = vi.fn();
    hanging.setTimeout = vi.fn((ms: number, cb: () => void) => {
      setTimeout(cb, ms);
      return hanging;
    });
    const netConnect = vi.fn(() => hanging);
    const outcome = await probeTcp("10.0.0.1", 443, 50, {
      lookup: vi.fn(),
      netConnect: netConnect as typeof import("node:net").connect,
      tlsConnect: vi.fn() as typeof import("node:tls").connect,
    });
    expect(outcome).toBe("blocked");
    expect(netConnect).toHaveBeenCalled();
  });

  it("reports reachable on ECONNRESET", async () => {
    const socket = new EventEmitter() as ReturnType<typeof import("node:net").connect>;
    socket.destroy = vi.fn();
    socket.setTimeout = vi.fn();
    const netConnect = vi.fn(() => {
      queueMicrotask(() => {
        socket.emit("error", Object.assign(new Error("reset"), { code: "ECONNRESET" }));
      });
      return socket;
    });
    const outcome = await probeTcp("10.0.0.2", 443, 2000, {
      lookup: vi.fn(),
      netConnect: netConnect as typeof import("node:net").connect,
      tlsConnect: vi.fn() as typeof import("node:tls").connect,
    });
    expect(outcome).toBe("reachable");
  });

  it("reports unresolved when lookup fails and never opens a socket", async () => {
    const netConnect = vi.fn();
    const lookup = vi
      .fn()
      .mockRejectedValue(Object.assign(new Error("nxdomain"), { code: "ENOTFOUND" }));
    const outcome = await probeTcp("missing.example", 443, 2000, {
      lookup: lookup as typeof import("node:dns/promises").lookup,
      netConnect: netConnect as typeof import("node:net").connect,
      tlsConnect: vi.fn() as typeof import("node:tls").connect,
    });
    expect(outcome).toBe("unresolved");
    expect(netConnect).not.toHaveBeenCalled();
  });
});

describe("probeTls", () => {
  function makeTlsFake(
    behavior: "secure" | "reset" | "hang",
    hostCapture: { servername?: string },
  ): typeof import("node:tls").connect {
    return vi.fn((options, callback) => {
      hostCapture.servername = options.servername;
      const socket = new EventEmitter() as import("node:tls").TLSSocket;
      socket.destroy = vi.fn();
      if (behavior === "hang") {
        socket.setTimeout = vi.fn((ms: number, cb: () => void) => {
          setTimeout(cb, ms);
          return socket;
        });
      } else {
        socket.setTimeout = vi.fn(() => socket);
      }
      queueMicrotask(() => {
        if (behavior === "secure") {
          callback?.();
        } else if (behavior === "reset") {
          socket.emit("error", Object.assign(new Error("reset"), { code: "ECONNRESET" }));
        }
      });
      return socket;
    }) as typeof import("node:tls").connect;
  }

  it("reports reachable on secureConnect and passes servername", async () => {
    const capture: { servername?: string } = {};
    const tlsConnect = makeTlsFake("secure", capture);
    const outcome = await probeTls("allowed.example", 443, 2000, {
      lookup: vi.fn().mockResolvedValue({ address: "93.184.216.34", family: 4 }),
      netConnect: vi.fn() as typeof import("node:net").connect,
      tlsConnect,
    });
    expect(outcome).toBe("reachable");
    expect(capture.servername).toBe("allowed.example");
  });

  it("reports blocked on reset before secureConnect", async () => {
    const capture: { servername?: string } = {};
    const tlsConnect = makeTlsFake("reset", capture);
    const outcome = await probeTls("allowed.example", 443, 2000, {
      lookup: vi.fn().mockResolvedValue({ address: "93.184.216.34", family: 4 }),
      netConnect: vi.fn() as typeof import("node:net").connect,
      tlsConnect,
    });
    expect(outcome).toBe("blocked");
  });

  it("reports blocked when the handshake never completes", async () => {
    const capture: { servername?: string } = {};
    const tlsConnect = makeTlsFake("hang", capture);
    const outcome = await probeTls("allowed.example", 443, 50, {
      lookup: vi.fn().mockResolvedValue({ address: "93.184.216.34", family: 4 }),
      netConnect: vi.fn() as typeof import("node:net").connect,
      tlsConnect,
    });
    expect(outcome).toBe("blocked");
  });
});

describe("buildChecks", () => {
  const checkIds = [
    "wire-server-80",
    "wire-server-32526",
    "imds-80",
    "apps-env-443",
    "kv-platform-443",
    "blob-pe-443",
    "kv-connections-443",
    "kv-delegated-443",
    "postgres-5432",
    "public-allowed-443",
    "public-canary-443",
    "public-port-25",
    "public-port-22",
    "public-port-8443",
    "dns-resolve",
  ] as const;

  function expectFor(id: (typeof checkIds)[number], cfg: ProbeConfig): string {
    const denyOnly = cfg.nsg !== "off";
    const enforce = cfg.nsg === "enforce";
    switch (id) {
      case "wire-server-80":
      case "wire-server-32526":
      case "imds-80":
      case "apps-env-443":
        return "informational";
      case "kv-platform-443":
      case "blob-pe-443":
        return denyOnly ? "blocked" : "informational";
      case "kv-connections-443":
      case "kv-delegated-443":
      case "postgres-5432":
      case "public-allowed-443":
      case "dns-resolve":
        return "reachable";
      case "public-canary-443":
        return cfg.fqdnAllowlist ? "blocked" : "reachable";
      case "public-port-25":
      case "public-port-22":
      case "public-port-8443":
        return enforce ? "blocked" : "informational";
      default:
        throw new Error(`unknown id ${id}`);
    }
  }

  it.each([
    { nsg: "off" as const, fqdnAllowlist: false },
    { nsg: "off" as const, fqdnAllowlist: true },
    { nsg: "deny-list-only" as const, fqdnAllowlist: false },
    { nsg: "deny-list-only" as const, fqdnAllowlist: true },
    { nsg: "enforce" as const, fqdnAllowlist: false },
    { nsg: "enforce" as const, fqdnAllowlist: true },
  ])("expectations for nsg=$nsg fqdnAllowlist=$fqdnAllowlist", ({ nsg, fqdnAllowlist }) => {
    const cfg = sampleConfig({ nsg, fqdnAllowlist, firewall: fqdnAllowlist || true });
    const specs = buildChecks(cfg);
    expect(specs.map((s) => s.id)).toEqual([...checkIds]);
    for (const id of checkIds) {
      const spec = specs.find((s) => s.id === id) as CheckSpec;
      expect(spec.expect).toBe(expectFor(id, cfg));
    }
  });
});

describe("parseConfig", () => {
  it("parses a complete environment", () => {
    const cfg = parseConfig(sampleEnv());
    expect(cfg.nsg).toBe("enforce");
    expect(cfg.timeoutMs).toBe(5000);
    expect(cfg.fqdnProtocol).toBe("tls");
  });

  it.each([
    "PROBE_EXPECT_NSG",
    "PROBE_EXPECT_FIREWALL",
    "PROBE_EXPECT_FQDN_ALLOWLIST",
    "PROBE_APPS_IP",
    "PROBE_KV_PLATFORM_IP",
    "PROBE_BLOB_PE_IP",
    "PROBE_KV_CONNECTIONS_IP",
    "PROBE_KV_DELEGATED_IP",
    "PROBE_POSTGRES_HOST",
    "PROBE_ALLOWED_HOST",
    "PROBE_CANARY_HOST",
  ])("throws when %s is missing", (key) => {
    const env = sampleEnv();
    delete env[key];
    expect(() => parseConfig(env)).toThrow(key);
  });

  it("rejects fqdn allowlist without firewall", () => {
    expect(() =>
      parseConfig(
        sampleEnv({ PROBE_EXPECT_FQDN_ALLOWLIST: "true", PROBE_EXPECT_FIREWALL: "false" }),
      ),
    ).toThrow("PROBE_EXPECT_FQDN_ALLOWLIST");
  });

  it("rejects an invalid NSG mode", () => {
    expect(() => parseConfig(sampleEnv({ PROBE_EXPECT_NSG: "maybe" }))).toThrow("PROBE_EXPECT_NSG");
  });

  it("rejects a non-IP apps address", () => {
    expect(() => parseConfig(sampleEnv({ PROBE_APPS_IP: "not-an-ip" }))).toThrow("PROBE_APPS_IP");
  });
});

describe("main", () => {
  it("exits 0 when every non-informational check matches", async () => {
    const lines: string[] = [];
    const cfg = sampleConfig();
    const specs = buildChecks(cfg);
    const code = await netprobe.main(sampleEnv(), (line) => lines.push(line), {
      runChecks: async () =>
        specs.map((spec) => ({
          id: spec.id,
          target: spec.kind === "dns" ? spec.host : `${spec.host}:${spec.port}`,
          expected: spec.expect,
          actual: spec.expect === "informational" ? "blocked" : (spec.expect as "reachable"),
          ok: true,
        })),
    });
    expect(code).toBe(0);
    const last = JSON.parse(lines.at(-1) as string);
    expect(last.event).toBe("egress.netprobe_result");
    expect(last.ok).toBe(true);
    vi.restoreAllMocks();
  });

  it("exits 1 when a non-informational check mismatches", async () => {
    const lines: string[] = [];
    const cfg = sampleConfig();
    const specs = buildChecks(cfg);
    const flipped = specs.findIndex((spec) => spec.expect !== "informational");
    const code = await netprobe.main(sampleEnv(), (line) => lines.push(line), {
      runChecks: async () =>
        specs.map((spec, index) => ({
          id: spec.id,
          target: `${spec.host}:${spec.port}`,
          expected: spec.expect,
          actual: index === flipped ? "error" : (spec.expect as "reachable"),
          ok: index !== flipped,
        })),
    });
    expect(code).toBe(1);
    const checkLine = JSON.parse(lines[flipped] as string);
    expect(checkLine.ok).toBe(false);
    vi.restoreAllMocks();
  });

  it("exits 0 when only informational checks mismatch", async () => {
    const lines: string[] = [];
    const cfg = sampleConfig({ nsg: "off" });
    const specs = buildChecks(cfg);
    const code = await netprobe.main(
      { ...sampleEnv(), PROBE_EXPECT_NSG: "off" },
      (line) => lines.push(line),
      {
        runChecks: async () =>
          specs.map((spec) => ({
            id: spec.id,
            target: spec.kind === "dns" ? spec.host : `${spec.host}:${spec.port}`,
            expected: spec.expect,
            actual: "reachable",
            ok: spec.expect === "informational" || spec.expect === "reachable",
          })),
      },
    );
    expect(code).toBe(0);
    vi.restoreAllMocks();
  });

  it("returns 2 on config error without stdout output", async () => {
    const lines: string[] = [];
    const code = await netprobe.main({}, (line) => lines.push(line));
    expect(code).toBe(2);
    expect(lines).toHaveLength(0);
  });

  it("never leaks secrets from unrelated environment variables", async () => {
    const lines: string[] = [];
    const cfg = sampleConfig();
    const specs = buildChecks(cfg);
    await netprobe.main(
      {
        ...sampleEnv(),
        DATABASE_URL: "postgres://u:supersecret@db/x",
      },
      (line) => lines.push(line),
      {
        runChecks: async () =>
          specs.map((spec) => ({
            id: spec.id,
            target: spec.host,
            expected: spec.expect,
            actual: "reachable",
            ok: spec.expect === "informational" || spec.expect === "reachable",
          })),
      },
    );
    const joined = lines.join("\n");
    expect(joined).not.toContain("supersecret");
    expect(joined).not.toContain("://");
    vi.restoreAllMocks();
  });
});

describe("runChecks", () => {
  it("marks informational expectations ok even when actual differs", async () => {
    const specs: CheckSpec[] = [
      { id: "apps-env-443", kind: "tcp", host: "10.0.2.1", port: 443, expect: "informational" },
    ];
    const results = await runChecks(specs, sampleConfig(), {
      lookup: vi.fn() as typeof import("node:dns/promises").lookup,
      netConnect: vi.fn() as typeof import("node:net").connect,
      tlsConnect: vi.fn() as typeof import("node:tls").connect,
      probeTcp: vi.fn().mockResolvedValue("reachable"),
    });
    expect(results[0]?.ok).toBe(true);
  });
});
