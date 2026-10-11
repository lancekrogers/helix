/**
 * Local egress NSG simulation: Docker subnets, iptables on the probe OUTPUT chain,
 * and the real netprobe entry point against stand-in listeners.
 *
 * Proves rule ordering and first-match logic, DROP (timeout) vs reset handling,
 * positive controls under the deny list, and that the probe fails when the table
 * is wrong. Does not prove Azure NSG semantics (statefulness, default or augmented
 * rules, service-tag membership), NSG attachment on a populated Container Apps
 * subnet, which platform flows ACA needs, behavior of 168.63.129.16 from a replica
 * (stand-ins answer because this simulation says they do), edge-to-egress source
 * addresses through the ILB, inbound rules (not exercised), or `just infra net-verify`
 * (operator-only, unverified in Azure by this tooling).
 *
 * Azure exempts DNS to 168.63.129.16 and Wire Server ports 80/32526, and IMDS at
 * 169.254.169.254, from prefix-based NSG rules; the translator models that so
 * removing allow-azure-dns does not mirror a real Azure failure.
 *
 * Run on a host with Docker (`just infra net-sim`). Static checks: `node --test
 * infra/netsim/translate.test.mjs` or `just infra net-sim --static` (no daemon required).
 */

import { spawnSync, execFileSync } from "node:child_process";
import { copyFileSync, readFileSync, statSync, unlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const PREFIX = "helix-netsim";
const IMAGE = "helix-netsim";
const layout = JSON.parse(readFileSync(join(here, "networks.json"), "utf8"));

function parseArgs(argv) {
  const opts = {
    static: false,
    keep: false,
    scenario: null,
    rules: join(repoRoot, "infra/azure/nsg-egress-rules.json"),
  };
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--static") {
      opts.static = true;
    } else if (arg === "--keep") {
      opts.keep = true;
    } else if (arg === "--scenario" && argv[i + 1]) {
      opts.scenario = argv[++i];
    } else if (arg === "--rules" && argv[i + 1]) {
      opts.rules = argv[++i];
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return opts;
}

function docker(...args) {
  return execFileSync("docker", args, { encoding: "utf8" }).trim();
}

function dockerOk(...args) {
  return spawnSync("docker", args, { encoding: "utf8" });
}

function teardown() {
  const names = docker("ps", "-a", "--format", "{{.Names}}")
    .split("\n")
    .filter((n) => n.startsWith(`${PREFIX}-`));
  for (const name of names) {
    try {
      docker("rm", "-f", name);
    } catch {
      /* already gone */
    }
  }
  const nets = docker("network", "ls", "--format", "{{.Name}}")
    .split("\n")
    .filter((n) => n.startsWith(`${PREFIX}-`));
  for (const net of nets) {
    try {
      docker("network", "rm", net);
    } catch {
      /* in use */
    }
  }
}

function buildImage() {
  docker("build", "-t", IMAGE, here);
}

function createNetworks() {
  for (const [name, { subnet }] of Object.entries(layout.networks)) {
    docker("network", "create", "--internal", "--subnet", subnet, `${PREFIX}-${name}`);
  }
}

function startStandins() {
  for (const standin of layout.standins) {
    const name = `${PREFIX}-${standin.name}`;
    dockerOk(
      "run",
      "-d",
      "--name",
      name,
      "--network",
      `${PREFIX}-${standin.network}`,
      "--ip",
      standin.ip,
      "-v",
      `${here}:/sim:ro`,
      IMAGE,
      "node",
      "/sim/listener.mjs",
      ...standin.listen.map(String),
    );
    if (standin.dns) {
      const addrArgs = Object.entries(layout.names)
        .map(([host, ip]) => `--address=/${host}/${ip}`)
        .join(" ");
      spawnSync("docker", [
        "exec",
        name,
        "sh",
        "-c",
        `dnsmasq -k --no-resolv --no-hosts ${addrArgs} &`,
      ]);
    }
  }
}

const PROBE_NET_IPS = {
  apps: "10.0.2.20",
  postgres: "10.0.6.20",
  pe: "10.0.7.20",
  platform: "168.63.129.20",
  imds: "169.254.169.20",
  public: "198.51.100.20",
};

function startProbe(rulesHostPath) {
  const probeName = `${PREFIX}-probe`;
  dockerOk(
    "run",
    "-d",
    "--name",
    probeName,
    "--cap-add",
    "NET_ADMIN",
    "--network",
    `${PREFIX}-${layout.probe.network}`,
    "--ip",
    layout.probe.ip,
    "-v",
    `${here}:/sim:ro`,
    "-v",
    `${rulesHostPath}:/rules-table.json:ro`,
    "-v",
    `${join(repoRoot, "apps/egress/src/netprobe.ts")}:/probe/netprobe.ts:ro`,
    IMAGE,
    "sleep",
    "infinity",
  );
  let imdsOnPlatform = false;
  for (const [net, ip] of Object.entries(PROBE_NET_IPS)) {
    if (net === layout.probe.network) {
      continue;
    }
    const r = dockerOk("network", "connect", "--ip", ip, `${PREFIX}-${net}`, probeName);
    if (r.status !== 0 && net === "imds") {
      imdsOnPlatform = true;
    } else if (r.status !== 0) {
      throw new Error(r.stderr || `failed to connect probe to ${net}`);
    }
  }
  if (imdsOnPlatform) {
    const ifname = docker(
      "exec",
      probeName,
      "sh",
      "-c",
      "ip -o route get 168.63.129.16 | awk '{print $3}'",
    );
    spawnSync("docker", [
      "exec",
      probeName,
      "ip",
      "route",
      "add",
      "169.254.169.254/32",
      "dev",
      ifname,
    ]);
  }
  return probeName;
}

function peEnv(pinning) {
  if (pinning === "dynamic") {
    return { PROBE_PE_ADDRESSES: "dynamic" };
  }
  return {
    PROBE_PE_ADDRESSES: "pinned",
    PROBE_KV_PLATFORM_IP: "10.0.7.4",
    PROBE_BLOB_PE_IP: "10.0.7.7",
    PROBE_KV_CONNECTIONS_IP: "10.0.7.5",
    PROBE_KV_DELEGATED_IP: "10.0.7.6",
  };
}

function baseProbeEnv(expectNsg, peMode) {
  return {
    PROBE_EXPECT_FIREWALL: "false",
    PROBE_EXPECT_FQDN_ALLOWLIST: "false",
    PROBE_FQDN_PROTOCOL: "tcp",
    PROBE_TIMEOUT_MS: "2000",
    PROBE_EXPECT_NSG: expectNsg,
    PROBE_APPS_IP: "10.0.2.10",
    PROBE_POSTGRES_HOST: "pg.sim.test",
    PROBE_ALLOWED_HOST: "allowed.sim.test",
    PROBE_CANARY_HOST: "canary.sim.test",
    PROBE_CLOSING_DENY_TARGET: "allowed.sim.test:8443",
    ...peEnv(peMode),
  };
}

const SCENARIOS = [
  {
    name: "off",
    mode: "off",
    pinning: "pinned",
    expectNsg: "off",
    peMode: "pinned",
    wantExit: 0,
    denyProven: false,
  },
  {
    name: "deny-list-only",
    mode: "deny-list-only",
    pinning: "pinned",
    expectNsg: "deny-list-only",
    peMode: "pinned",
    wantExit: 0,
    denyProven: true,
  },
  {
    name: "enforce",
    mode: "enforce",
    pinning: "pinned",
    expectNsg: "enforce",
    peMode: "pinned",
    wantExit: 0,
    denyProven: true,
  },
  {
    name: "deny-list-only-unpinned",
    mode: "deny-list-only",
    pinning: "unpinned",
    expectNsg: "deny-list-only",
    peMode: "dynamic",
    wantExit: 0,
    denyProven: false,
  },
  {
    name: "break-kv",
    mode: "enforce",
    pinning: "pinned",
    break: "remove:allow-key-vault-endpoints",
    expectNsg: "enforce",
    peMode: "pinned",
    wantExit: 1,
    failCheck: { id: "kv-connections-443", actual: "blocked" },
  },
  {
    name: "break-order",
    mode: "enforce",
    pinning: "pinned",
    break: "renumber:deny-vnet:105",
    expectNsg: "enforce",
    peMode: "pinned",
    wantExit: 1,
    failCheck: { id: "postgres-5432", actual: "blocked" },
  },
  {
    name: "broken-closing-deny",
    mode: "deny-list-only",
    pinning: "pinned",
    expectNsg: "enforce",
    peMode: "pinned",
    wantExit: 1,
    failCheck: { id: "closing-deny", actual: "reachable" },
  },
  {
    name: "nsg-detached",
    mode: "off",
    pinning: "pinned",
    expectNsg: "deny-list-only",
    peMode: "pinned",
    wantExit: 1,
    failCheck: { id: "blob-pe-443", actual: "reachable" },
  },
];

function parseProbeLines(stdout) {
  const checks = new Map();
  let summary = null;
  for (const line of stdout.split("\n")) {
    if (!line.trim()) {
      continue;
    }
    try {
      const obj = JSON.parse(line);
      if (obj.event === "egress.netprobe_check") {
        checks.set(obj.check, obj);
      } else if (obj.event === "egress.netprobe_result") {
        summary = obj;
      }
    } catch {
      /* not JSON */
    }
  }
  return { checks, summary };
}

function runScenario(probeName, scenario, rulesInContainer) {
  const applyArgs = [
    "exec",
    probeName,
    "node",
    "/sim/apply.mjs",
    "--mode",
    scenario.mode,
    "--pinning",
    scenario.pinning,
    "--rules",
    rulesInContainer,
  ];
  if (scenario.break) {
    applyArgs.push("--break", scenario.break);
  }
  const apply = dockerOk(...applyArgs);
  if (apply.status !== 0) {
    throw new Error(apply.stderr || "apply.mjs failed");
  }

  const env = baseProbeEnv(scenario.expectNsg, scenario.peMode);
  const execArgs = ["exec"];
  for (const [k, v] of Object.entries(env)) {
    execArgs.push("-e", `${k}=${v}`);
  }
  execArgs.push(probeName, "node", "--experimental-strip-types", "/probe/netprobe.ts");
  const r = spawnSync("docker", execArgs, { encoding: "utf8" });
  const exitCode = r.status ?? 1;
  const { checks, summary } = parseProbeLines(r.stdout);

  let ok = exitCode === scenario.wantExit;
  let detail = `exit ${exitCode} (want ${scenario.wantExit})`;
  const denyExpect = scenario.denyProven;
  if (denyExpect !== undefined && summary) {
    if (summary.denyProven !== denyExpect) {
      ok = false;
      detail += `; denyProven=${summary.denyProven} want ${denyExpect}`;
    }
  } else if (denyExpect !== undefined) {
    ok = false;
    detail += "; missing egress.netprobe_result";
  }
  if (scenario.failCheck) {
    const row = checks.get(scenario.failCheck.id);
    if (!row) {
      ok = false;
      detail += `; missing check ${scenario.failCheck.id}`;
    } else if (row.actual !== scenario.failCheck.actual) {
      ok = false;
      detail += `; ${scenario.failCheck.id} actual=${row.actual} want ${scenario.failCheck.actual}`;
    }
  }

  return { ok, detail, stdout: r.stdout, stderr: r.stderr };
}

function runStatic() {
  const r = spawnSync("node", ["--test", "infra/netsim/translate.test.mjs"], {
    encoding: "utf8",
    cwd: repoRoot,
  });
  process.stdout.write(r.stdout);
  process.stderr.write(r.stderr);
  if (r.status !== 0) {
    process.exit(r.status ?? 1);
  }
}

const opts = parseArgs(process.argv);

if (opts.static) {
  runStatic();
  process.exit(0);
}

runStatic();

try {
  const st = statSync(opts.rules);
  if (!st.isFile()) {
    throw new Error(`--rules must be a file: ${opts.rules}`);
  }
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
}

const info = dockerOk("info");
if (info.status !== 0) {
  console.error("Docker daemon not available. Run net-sim on a host with Docker.");
  process.exit(1);
}

let failed = false;
const mountedRules = join(here, ".docker-rules.json");
try {
  teardown();
  copyFileSync(opts.rules, mountedRules);
  buildImage();
  createNetworks();
  startStandins();
  const rulesInContainer = "/rules-table.json";
  const probeName = startProbe(mountedRules);

  const list = opts.scenario ? SCENARIOS.filter((s) => s.name === opts.scenario) : SCENARIOS;
  if (list.length === 0) {
    throw new Error(`unknown scenario: ${opts.scenario}`);
  }

  console.log("scenario\tresult\tdetail");
  for (const scenario of list) {
    const result = runScenario(probeName, scenario, rulesInContainer);
    console.log(`${scenario.name}\t${result.ok ? "PASS" : "FAIL"}\t${result.detail}`);
    if (!result.ok) {
      failed = true;
      if (result.stderr) {
        process.stderr.write(result.stderr);
      }
    }
  }
} finally {
  if (!opts.keep) {
    teardown();
  }
  try {
    unlinkSync(mountedRules);
  } catch {
    /* already removed */
  }
}

process.exit(failed ? 1 : 0);
