import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadRules, toIptables, applyBreak } from "./translate.mjs";

const here = dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  let mode = "off";
  let breakSpec = null;
  let rulesPath = join(here, "nsg-egress-rules.json");
  let pinning = "pinned";
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--mode" && argv[i + 1]) {
      mode = argv[++i];
    } else if (arg === "--break" && argv[i + 1]) {
      breakSpec = argv[++i];
    } else if (arg === "--rules" && argv[i + 1]) {
      rulesPath = argv[++i];
    } else if (arg === "--pinning" && argv[i + 1]) {
      pinning = argv[++i];
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return { mode, breakSpec, rulesPath, pinning };
}

const { mode, breakSpec, rulesPath, pinning } = parseArgs(process.argv);

const layout = JSON.parse(readFileSync(join(here, "networks.json"), "utf8"));
let rules = loadRules(JSON.parse(readFileSync(rulesPath, "utf8")));
if (breakSpec) {
  rules = applyBreak(rules, breakSpec);
}

const ctx = {
  refs: layout.refs,
  tags: layout.tags,
  allowedPorts: layout.allowedPorts,
};

const iptablesLines = toIptables(rules, mode, ctx, pinning);
for (const args of iptablesLines) {
  execFileSync("iptables", args, { stdio: "inherit" });
}

writeFileSync("/etc/resolv.conf", "nameserver 168.63.129.16\n");
process.stdout.write(`${iptablesLines.length}\n`);
