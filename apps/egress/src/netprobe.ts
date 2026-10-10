import { lookup } from "node:dns/promises";
import { connect as netConnect, isIP, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { pathToFileURL } from "node:url";

export type Outcome = "blocked" | "reachable" | "unresolved" | "error";
export type Expectation = Outcome | "informational";
export type NsgMode = "off" | "deny-list-only" | "enforce";
export type PeAddressesMode = "pinned" | "dynamic";

const PE_IP_ENV_KEYS = [
  "PROBE_KV_PLATFORM_IP",
  "PROBE_BLOB_PE_IP",
  "PROBE_KV_CONNECTIONS_IP",
  "PROBE_KV_DELEGATED_IP",
] as const;

export interface ProbeConfig {
  nsg: NsgMode;
  firewall: boolean;
  fqdnAllowlist: boolean;
  fqdnProtocol: "tls" | "tcp";
  peAddresses: PeAddressesMode;
  appsIp: string;
  kvPlatformIp: string;
  blobIp: string;
  kvConnectionsIp: string;
  kvDelegatedIp: string;
  postgresHost: string;
  allowedHost: string;
  canaryHost: string;
  timeoutMs: number;
}

export interface CheckSpec {
  id: string;
  kind: "tcp" | "tls" | "dns";
  host: string;
  port: number;
  expect: Expectation;
}

export interface CheckResult {
  id: string;
  target: string;
  expected: Expectation;
  actual: Outcome;
  ok: boolean;
}

export type ProbeDeps = {
  lookup: typeof lookup;
  netConnect: typeof netConnect;
  tlsConnect: typeof tlsConnect;
  probeTcp?: typeof probeTcp;
  probeTls?: typeof probeTls;
  probeDns?: typeof probeDns;
};

const HOST_RE = /^[a-z0-9.-]+$/i;
const NSG_VALUES: readonly NsgMode[] = ["off", "deny-list-only", "enforce"];

function requireEnv(env: Record<string, string | undefined>, key: string): string {
  const value = env[key];
  if (value === undefined || value === "") {
    throw new Error(`${key} is required`);
  }
  return value;
}

function parseBool(env: Record<string, string | undefined>, key: string): boolean {
  const value = requireEnv(env, key);
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  throw new Error(`${key} must be "true" or "false"`);
}

function parseIp(env: Record<string, string | undefined>, key: string): string {
  const value = requireEnv(env, key);
  if (isIP(value) === 0) {
    throw new Error(`${key} must be a valid IP address`);
  }
  return value;
}

function parseHost(env: Record<string, string | undefined>, key: string): string {
  const value = requireEnv(env, key);
  if (!HOST_RE.test(value)) {
    throw new Error(`${key} must be a hostname`);
  }
  return value;
}

function parsePeAddressesMode(env: Record<string, string | undefined>): PeAddressesMode {
  const value = requireEnv(env, "PROBE_PE_ADDRESSES");
  if (value === "pinned" || value === "dynamic") {
    return value;
  }
  throw new Error('PROBE_PE_ADDRESSES must be "pinned" or "dynamic"');
}

function peIpEnvSet(env: Record<string, string | undefined>, key: string): boolean {
  const value = env[key];
  return value !== undefined && value !== "";
}

export function parseConfig(env: Record<string, string | undefined>): ProbeConfig {
  const nsgRaw = requireEnv(env, "PROBE_EXPECT_NSG");
  if (!NSG_VALUES.includes(nsgRaw as NsgMode)) {
    throw new Error("PROBE_EXPECT_NSG must be off, deny-list-only, or enforce");
  }
  const nsg = nsgRaw as NsgMode;

  const firewall = parseBool(env, "PROBE_EXPECT_FIREWALL");
  const fqdnAllowlist = parseBool(env, "PROBE_EXPECT_FQDN_ALLOWLIST");
  if (fqdnAllowlist && !firewall) {
    throw new Error("PROBE_EXPECT_FQDN_ALLOWLIST=true requires PROBE_EXPECT_FIREWALL=true");
  }

  const fqdnProtocolRaw = env.PROBE_FQDN_PROTOCOL ?? "tls";
  if (fqdnProtocolRaw !== "tls" && fqdnProtocolRaw !== "tcp") {
    throw new Error('PROBE_FQDN_PROTOCOL must be "tls" or "tcp"');
  }
  const fqdnProtocol = fqdnProtocolRaw as "tls" | "tcp";

  const timeoutRaw = env.PROBE_TIMEOUT_MS ?? "5000";
  const timeoutMs = Number(timeoutRaw);
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error("PROBE_TIMEOUT_MS must be a positive integer");
  }

  const peAddresses = parsePeAddressesMode(env);
  const anyPeIpSet = PE_IP_ENV_KEYS.some((key) => peIpEnvSet(env, key));

  let kvPlatformIp = "";
  let blobIp = "";
  let kvConnectionsIp = "";
  let kvDelegatedIp = "";
  if (peAddresses === "pinned") {
    kvPlatformIp = parseIp(env, "PROBE_KV_PLATFORM_IP");
    blobIp = parseIp(env, "PROBE_BLOB_PE_IP");
    kvConnectionsIp = parseIp(env, "PROBE_KV_CONNECTIONS_IP");
    kvDelegatedIp = parseIp(env, "PROBE_KV_DELEGATED_IP");
  } else if (anyPeIpSet) {
    throw new Error(
      "PROBE_PE_ADDRESSES=dynamic requires PROBE_KV_PLATFORM_IP, PROBE_BLOB_PE_IP, PROBE_KV_CONNECTIONS_IP, and PROBE_KV_DELEGATED_IP to be unset or empty",
    );
  }

  const cfg: ProbeConfig = {
    nsg,
    firewall,
    fqdnAllowlist,
    fqdnProtocol,
    peAddresses,
    appsIp: parseIp(env, "PROBE_APPS_IP"),
    kvPlatformIp,
    blobIp,
    kvConnectionsIp,
    kvDelegatedIp,
    postgresHost: parseHost(env, "PROBE_POSTGRES_HOST"),
    allowedHost: parseHost(env, "PROBE_ALLOWED_HOST"),
    canaryHost: parseHost(env, "PROBE_CANARY_HOST"),
    timeoutMs,
  };

  return cfg;
}

export function buildChecks(cfg: ProbeConfig): CheckSpec[] {
  const denyOnly = cfg.nsg !== "off";
  const enforce = cfg.nsg === "enforce";
  // Azure does not apply NSG rules to the host-node addresses: 168.63.129.16 on
  // ports 80 and 32526 is exempt outright, and IMDS is filtered only by the
  // AzurePlatformIMDS service tag, not by an address prefix. The application
  // block list (ssrf.ts) is the control for both, so these checks only record
  // what the replica sees.
  const hostNodeExpect: Expectation = "informational";
  const blobPeExpect: Expectation = denyOnly ? "blocked" : "informational";
  const portExpect: Expectation = enforce ? "blocked" : "informational";
  const canaryExpect: Expectation = cfg.fqdnAllowlist ? "blocked" : "reachable";
  const fqdnKind: "tcp" | "tls" = cfg.fqdnProtocol === "tls" ? "tls" : "tcp";

  const checks: CheckSpec[] = [
    { id: "wire-server-80", kind: "tcp", host: "168.63.129.16", port: 80, expect: hostNodeExpect },
    {
      id: "wire-server-32526",
      kind: "tcp",
      host: "168.63.129.16",
      port: 32526,
      expect: hostNodeExpect,
    },
    { id: "imds-80", kind: "tcp", host: "169.254.169.254", port: 80, expect: hostNodeExpect },
    { id: "apps-env-443", kind: "tcp", host: cfg.appsIp, port: 443, expect: "informational" },
  ];

  if (cfg.peAddresses === "pinned") {
    // kv-platform is allowed when pinning is on (egress Key Vault references); blob stays denied.
    checks.push(
      {
        id: "kv-platform-443",
        kind: "tcp",
        host: cfg.kvPlatformIp,
        port: 443,
        expect: "reachable",
      },
      { id: "blob-pe-443", kind: "tcp", host: cfg.blobIp, port: 443, expect: blobPeExpect },
      {
        id: "kv-connections-443",
        kind: "tcp",
        host: cfg.kvConnectionsIp,
        port: 443,
        expect: "reachable",
      },
      {
        id: "kv-delegated-443",
        kind: "tcp",
        host: cfg.kvDelegatedIp,
        port: 443,
        expect: "reachable",
      },
    );
  }

  checks.push(
    { id: "postgres-5432", kind: "tcp", host: cfg.postgresHost, port: 5432, expect: "reachable" },
    {
      id: "public-allowed-443",
      kind: fqdnKind,
      host: cfg.allowedHost,
      port: 443,
      expect: "reachable",
    },
    {
      id: "public-canary-443",
      kind: fqdnKind,
      host: cfg.canaryHost,
      port: 443,
      expect: canaryExpect,
    },
    {
      id: "public-port-25",
      kind: "tcp",
      host: cfg.allowedHost,
      port: 25,
      expect: portExpect,
    },
    {
      id: "public-port-22",
      kind: "tcp",
      host: cfg.allowedHost,
      port: 22,
      expect: portExpect,
    },
    {
      id: "public-port-8443",
      kind: "tcp",
      host: cfg.allowedHost,
      port: 8443,
      expect: portExpect,
    },
    { id: "dns-resolve", kind: "dns", host: cfg.allowedHost, port: 0, expect: "reachable" },
  );

  return checks;
}

export function classify(error: NodeJS.ErrnoException | undefined, timedOut: boolean): Outcome {
  if (timedOut) {
    return "blocked";
  }
  if (error === undefined) {
    return "reachable";
  }
  const code = error.code;
  if (code === "ETIMEDOUT") {
    return "blocked";
  }
  if (code === "ECONNREFUSED" || code === "ECONNRESET") {
    return "reachable";
  }
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") {
    return "unresolved";
  }
  return "error";
}

async function resolveHost(
  host: string,
  deps: ProbeDeps,
): Promise<{ address: string } | { outcome: Outcome }> {
  if (isIP(host) !== 0) {
    return { address: host };
  }
  try {
    const result = await deps.lookup(host);
    const address = result.address;
    if (!address) {
      return { outcome: "error" };
    }
    return { address };
  } catch (err) {
    return { outcome: classify(err as NodeJS.ErrnoException, false) };
  }
}

export async function probeTcp(
  host: string,
  port: number,
  timeoutMs: number,
  deps: ProbeDeps = { lookup, netConnect, tlsConnect },
): Promise<Outcome> {
  const resolved = await resolveHost(host, deps);
  if ("outcome" in resolved) {
    return resolved.outcome;
  }

  return new Promise((resolve) => {
    let settled = false;
    const finish = (outcome: Outcome): void => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve(outcome);
    };

    const socket: Socket = deps.netConnect({ host: resolved.address, port });
    socket.setTimeout(timeoutMs, () => {
      finish(classify(undefined, true));
    });
    socket.once("connect", () => {
      finish("reachable");
    });
    socket.once("error", (err: NodeJS.ErrnoException) => {
      finish(classify(err, false));
    });
  });
}

export async function probeTls(
  host: string,
  port: number,
  timeoutMs: number,
  deps: ProbeDeps = { lookup, netConnect, tlsConnect },
): Promise<Outcome> {
  const resolved = await resolveHost(host, deps);
  if ("outcome" in resolved) {
    return resolved.outcome;
  }

  return new Promise((resolve) => {
    let settled = false;
    let handshakeDone = false;

    const finish = (outcome: Outcome): void => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve(outcome);
    };

    const socket: TLSSocket = deps.tlsConnect(
      {
        host: resolved.address,
        port,
        servername: host,
        rejectUnauthorized: false,
      },
      () => {
        handshakeDone = true;
        finish("reachable");
      },
    );

    socket.setTimeout(timeoutMs, () => {
      if (!handshakeDone) {
        finish("blocked");
      }
    });

    socket.once("error", (err: NodeJS.ErrnoException) => {
      if (handshakeDone) {
        finish("reachable");
        return;
      }
      if (err.code === "ECONNRESET") {
        finish("blocked");
        return;
      }
      finish(classify(err, false));
    });
  });
}

export async function probeDns(
  host: string,
  deps: ProbeDeps = { lookup, netConnect, tlsConnect },
): Promise<Outcome> {
  if (isIP(host) !== 0) {
    return "reachable";
  }
  try {
    await deps.lookup(host);
    return "reachable";
  } catch (err) {
    const outcome = classify(err as NodeJS.ErrnoException, false);
    if (outcome === "reachable") {
      return "error";
    }
    return outcome;
  }
}

export async function runChecks(
  specs: CheckSpec[],
  cfg: ProbeConfig,
  deps?: ProbeDeps,
): Promise<CheckResult[]> {
  const probeDeps = deps ?? { lookup, netConnect, tlsConnect };
  const results: CheckResult[] = [];

  const tcp = probeDeps.probeTcp ?? probeTcp;
  const tls = probeDeps.probeTls ?? probeTls;
  const dns = probeDeps.probeDns ?? probeDns;

  for (const spec of specs) {
    let actual: Outcome;
    if (spec.kind === "dns") {
      actual = await dns(spec.host, probeDeps);
    } else if (spec.kind === "tls") {
      actual = await tls(spec.host, spec.port, cfg.timeoutMs, probeDeps);
    } else {
      actual = await tcp(spec.host, spec.port, cfg.timeoutMs, probeDeps);
    }

    const target = spec.kind === "dns" ? spec.host : `${spec.host}:${spec.port}`;
    const ok = spec.expect === "informational" || spec.expect === actual;
    results.push({
      id: spec.id,
      target,
      expected: spec.expect,
      actual,
      ok,
    });
  }

  return results;
}

function formatCheckLine(result: CheckResult): string {
  return JSON.stringify({
    event: "egress.netprobe_check",
    time: new Date().toISOString(),
    check: result.id,
    target: result.target,
    expected: result.expected,
    actual: result.actual,
    ok: result.ok,
  });
}

function formatSummaryLine(cfg: ProbeConfig, results: CheckResult[]): string {
  const failed = results.filter((r) => !r.ok).length;
  const allOk = failed === 0;
  return JSON.stringify({
    event: "egress.netprobe_result",
    time: new Date().toISOString(),
    ok: allOk,
    checks: results.length,
    failed,
    nsg: cfg.nsg,
    firewall: cfg.firewall,
    fqdnAllowlist: cfg.fqdnAllowlist,
    peAddresses: cfg.peAddresses,
  });
}

export type MainHooks = {
  runChecks?: typeof runChecks;
};

export async function main(
  env: Record<string, string | undefined>,
  write: (line: string) => void,
  hooks?: MainHooks,
): Promise<number> {
  let cfg: ProbeConfig;
  try {
    cfg = parseConfig(env);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`${message}\n`);
    return 2;
  }

  const specs = buildChecks(cfg);
  const run = hooks?.runChecks ?? runChecks;
  const results = await run(specs, cfg);

  for (const result of results) {
    write(formatCheckLine(result));
  }
  write(formatSummaryLine(cfg, results));

  const failed = results.some((r) => !r.ok);
  return failed ? 1 : 0;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.env, (line) => {
    process.stdout.write(`${line}\n`);
  });
}
