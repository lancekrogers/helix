import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { activeRules, applyBreak, loadRules, resolveRule, toIptables } from "./translate.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const rulesJson = JSON.parse(
  readFileSync(join(repoRoot, "infra/azure/nsg-egress-rules.json"), "utf8"),
);
const layout = JSON.parse(readFileSync(join(here, "networks.json"), "utf8"));
const rules = loadRules(rulesJson);
const ctx = {
  refs: layout.refs,
  tags: layout.tags,
  allowedPorts: layout.allowedPorts,
};

function ruleByName(name) {
  const r = rules.find((x) => x.name === name);
  assert.ok(r, `missing rule ${name}`);
  return r;
}

function prioritiesForPinning(pinning, mode) {
  const pairs = [];
  for (const rule of activeRules(rules, mode, pinning)) {
    pairs.push({ direction: rule.direction, priority: rule.priority, name: rule.name });
  }
  return pairs;
}

function assertUniquePriorities(pinning, mode) {
  const pairs = prioritiesForPinning(pinning, mode);
  const seen = new Set();
  for (const { direction, priority, name } of pairs) {
    const key = `${direction}:${priority}`;
    assert.ok(!seen.has(key), `duplicate ${key} (${name}) in pinning=${pinning} mode=${mode}`);
    seen.add(key);
  }
}

test("every (direction, priority) is unique within pinned variant", () => {
  for (const mode of ["deny-list-only", "enforce"]) {
    assertUniquePriorities("pinned", mode);
  }
});

test("every (direction, priority) is unique within unpinned variant", () => {
  for (const mode of ["deny-list-only", "enforce"]) {
    assertUniquePriorities("unpinned", mode);
  }
});

test("every $-ref in the rule file exists in networks.json refs", () => {
  const refKeys = new Set(Object.keys(layout.refs));
  for (const rule of rules) {
    for (const list of [rule.sourcePrefixes, rule.destinationPrefixes]) {
      for (const p of list) {
        if (p.startsWith("$") && p !== "$allowedPorts") {
          assert.ok(refKeys.has(p), `missing ref ${p} for rule ${rule.name}`);
        }
      }
    }
    for (const p of rule.destinationPorts) {
      if (p.startsWith("$")) {
        assert.equal(p, "$allowedPorts");
      }
    }
  }
});

test("every non-literal destination prefix is a known tag or ref", () => {
  const known = new Set([
    ...Object.keys(layout.refs),
    ...Object.keys(layout.tags),
    "*",
    "168.63.129.16",
    "169.254.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
  ]);
  for (const rule of rules) {
    for (const p of rule.destinationPrefixes) {
      if (!p.startsWith("$") && !known.has(p) && !/^\d/.test(p)) {
        assert.ok(layout.tags[p], `unknown tag ${p} in ${rule.name}`);
      }
    }
    for (const p of rule.sourcePrefixes) {
      if (!p.startsWith("$") && p !== "*" && !known.has(p) && !/^\d/.test(p)) {
        assert.ok(layout.tags[p], `unknown source tag ${p} in ${rule.name}`);
      }
    }
  }
});

test("no deny-wire-server row (Microsoft warns against denying 168.63.129.16 on ACA subnets)", () => {
  assert.ok(!rules.some((r) => r.name === "deny-wire-server"));
});

test("allow-apps-subnet includes ILB backend ports 31080 and 31443", () => {
  const ports = ruleByName("allow-apps-subnet").destinationPorts;
  assert.ok(ports.includes("31080"));
  assert.ok(ports.includes("31443"));
});

test("deny-vnet-in and deny-cgnat are enforce-only", () => {
  assert.deepEqual(ruleByName("deny-vnet-in").modes, ["enforce"]);
  assert.deepEqual(ruleByName("deny-cgnat").modes, ["enforce"]);
});

test("allow-key-vault-endpoints resolves pinned vault IPs", () => {
  const resolved = resolveRule(ruleByName("allow-key-vault-endpoints"), ctx);
  assert.deepEqual(resolved.dst, ["10.0.7.4", "10.0.7.5", "10.0.7.6"]);
});

test("deny-vnet is after postgres, vault, dns and own-subnet allows", () => {
  const deny = ruleByName("deny-vnet").priority;
  for (const name of [
    "allow-own-subnet",
    "allow-postgres",
    "allow-key-vault-endpoints",
    "allow-azure-dns",
  ]) {
    assert.ok(ruleByName(name).priority < deny, `${name} should be above deny-vnet`);
  }
});

test("deny-all-outbound in enforce only", () => {
  const closing = ruleByName("deny-all-outbound");
  assert.ok(closing.modes.includes("enforce"));
  assert.ok(!closing.modes.includes("deny-list-only"));
});

test("off mode yields no NSG rows (only baseline chains)", () => {
  const lines = toIptables(rules, "off", ctx);
  assert.equal(lines.length, 9);
  assert.deepEqual(lines[0], ["-F", "OUTPUT"]);
  assert.deepEqual(lines.at(-1), ["-A", "OUTPUT", "-j", "ACCEPT"]);
});

test("golden: allow-postgres", () => {
  const lines = toIptables(rules, "enforce", ctx);
  assert.ok(
    lines.some((l) => l.join(" ") === "-A OUTPUT -p tcp -d 10.0.6.0/24 --dport 5432 -j ACCEPT"),
  );
});

test("golden: deny-private-ranges (three DROP rules)", () => {
  const lines = toIptables(rules, "enforce", ctx);
  const drops = lines.filter((l) => l.at(-1) === "DROP" && l.includes("10.0.0.0/8"));
  assert.equal(drops.length, 1);
  assert.ok(lines.some((l) => l.join(" ") === "-A OUTPUT -d 10.0.0.0/8 -j DROP"));
  assert.ok(lines.some((l) => l.join(" ") === "-A OUTPUT -d 172.16.0.0/12 -j DROP"));
  assert.ok(lines.some((l) => l.join(" ") === "-A OUTPUT -d 192.168.0.0/16 -j DROP"));
});

test("golden: allow-internet-web", () => {
  const lines = toIptables(rules, "enforce", ctx);
  assert.ok(
    lines.some((l) => l.join(" ") === "-A OUTPUT -p tcp -d 0.0.0.0/0 --dport 80 -j ACCEPT"),
  );
  assert.ok(
    lines.some((l) => l.join(" ") === "-A OUTPUT -p tcp -d 0.0.0.0/0 --dport 443 -j ACCEPT"),
  );
});

test("golden: allow-azure-dns tcp and udp 53", () => {
  const lines = toIptables(rules, "enforce", ctx);
  const azureExempt = lines.filter(
    (l) => l.includes("168.63.129.16") && l.includes("--dport") && l.includes("53"),
  );
  assert.ok(azureExempt.length >= 2);
  assert.ok(
    lines.some((l) => l.join(" ") === "-A OUTPUT -p tcp -d 168.63.129.16 --dport 53 -j ACCEPT"),
  );
  assert.ok(
    lines.some((l) => l.join(" ") === "-A OUTPUT -p udp -d 168.63.129.16 --dport 53 -j ACCEPT"),
  );
});

test("golden: deny-all-outbound", () => {
  const lines = toIptables(rules, "enforce", ctx);
  const idx = lines.findIndex((l) => l.join(" ") === "-A OUTPUT -j DROP");
  assert.ok(idx > 0);
  assert.deepEqual(lines.at(-1), ["-A", "OUTPUT", "-j", "ACCEPT"]);
});

test("golden: Azure host-node exemption lines before NSG rows", () => {
  const lines = toIptables(rules, "enforce", ctx);
  const firstNsg = lines.findIndex(
    (l) => l.includes("-d") && l.includes("10.0.4.0/23") && l.at(-1) === "ACCEPT",
  );
  const imdsExempt = lines.findIndex(
    (l) => l.join(" ") === "-A OUTPUT -d 169.254.169.254 -j ACCEPT",
  );
  assert.ok(imdsExempt > 2 && imdsExempt < firstNsg);
});

test("applyBreak remove and renumber", () => {
  const removed = applyBreak(rules, "remove:allow-azure-dns");
  assert.ok(!removed.some((r) => r.name === "allow-azure-dns"));
  const renumbered = applyBreak(rules, "renumber:deny-vnet:105");
  assert.equal(ruleByName("deny-vnet").priority, 220);
  assert.equal(renumbered.find((r) => r.name === "deny-vnet").priority, 105);
});

test("applyBreak rejects unknown name", () => {
  assert.throws(() => applyBreak(rules, "remove:no-such-rule"), /unknown rule name/);
});

test("pinned vs unpinned active rules at priority 120", () => {
  const pinned = activeRules(rules, "enforce", "pinned");
  const unpinned = activeRules(rules, "enforce", "unpinned");
  assert.ok(pinned.some((r) => r.name === "allow-key-vault-endpoints"));
  assert.ok(!pinned.some((r) => r.name === "allow-private-endpoints-subnet"));
  assert.ok(unpinned.some((r) => r.name === "allow-private-endpoints-subnet"));
  assert.ok(!unpinned.some((r) => r.name === "allow-key-vault-endpoints"));
});

test("resolveRule expands allowedPorts", () => {
  const internet = resolveRule(ruleByName("allow-internet-web"), ctx);
  assert.deepEqual(internet.ports, ["80", "443"]);
  assert.deepEqual(internet.dst, ["0.0.0.0/0"]);
});
