import { describe, expect, it } from "vitest";
import { isIP } from "node:net";
import { isBlockedAddress } from "./ssrf.js";

// Retrieved 2026-10-10 from
//   https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv
//   https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv

interface RegistryRow {
  block: string;
  name: string;
  forwardable: string;
  globallyReachable: string;
}

const EXPECTED_IANA_COLUMNS = [
  "Address Block",
  "Name",
  "RFC",
  "Allocation Date",
  "Termination Date",
  "Source",
  "Destination",
  "Forwardable",
  "Globally Reachable",
  "Reserved-by-Protocol",
] as const;

const IPV4_REGISTRY: RegistryRow[] = [
  { block: "0.0.0.0/8", name: '"This network"', forwardable: "False", globallyReachable: "False" },
  {
    block: "0.0.0.0/32",
    name: '"This host on this network"',
    forwardable: "False",
    globallyReachable: "False",
  },
  { block: "10.0.0.0/8", name: "Private-Use", forwardable: "True", globallyReachable: "False" },
  {
    block: "100.64.0.0/10",
    name: "Shared Address Space",
    forwardable: "True",
    globallyReachable: "False",
  },
  {
    block: "127.0.0.0/8",
    name: "Loopback",
    forwardable: "False [1]",
    globallyReachable: "False [1]",
  },
  { block: "169.254.0.0/16", name: "Link Local", forwardable: "False", globallyReachable: "False" },
  { block: "172.16.0.0/12", name: "Private-Use", forwardable: "True", globallyReachable: "False" },
  {
    block: "192.0.0.0/24",
    name: "IETF Protocol Assignments",
    forwardable: "False",
    globallyReachable: "False",
  },
  {
    block: "192.0.0.0/29",
    name: "IPv4 Service Continuity Prefix",
    forwardable: "True",
    globallyReachable: "False",
  },
  {
    block: "192.0.0.8/32",
    name: "IPv4 dummy address",
    forwardable: "False",
    globallyReachable: "False",
  },
  {
    block: "192.0.0.9/32",
    name: "Port Control Protocol Anycast",
    forwardable: "True",
    globallyReachable: "True",
  },
  {
    block: "192.0.0.10/32",
    name: "Traversal Using Relays around NAT Anycast",
    forwardable: "True",
    globallyReachable: "True",
  },
  {
    block: "192.0.0.170/32",
    name: "NAT64/DNS64 Discovery",
    forwardable: "False",
    globallyReachable: "False",
  },
  {
    block: "192.0.0.171/32",
    name: "NAT64/DNS64 Discovery",
    forwardable: "False",
    globallyReachable: "False",
  },
  {
    block: "192.0.2.0/24",
    name: "Documentation (TEST-NET-1)",
    forwardable: "False",
    globallyReachable: "False",
  },
  { block: "192.31.196.0/24", name: "AS112-v4", forwardable: "True", globallyReachable: "True" },
  { block: "192.52.193.0/24", name: "AMT", forwardable: "True", globallyReachable: "True" },
  {
    block: "192.88.99.0/24",
    name: "Deprecated (6to4 Relay Anycast)",
    forwardable: "",
    globallyReachable: "",
  },
  {
    block: "192.88.99.2/32",
    name: "6a44-relay anycast address",
    forwardable: "True",
    globallyReachable: "False",
  },
  { block: "192.168.0.0/16", name: "Private-Use", forwardable: "True", globallyReachable: "False" },
  {
    block: "192.175.48.0/24",
    name: "Direct Delegation AS112 Service",
    forwardable: "True",
    globallyReachable: "True",
  },
  { block: "198.18.0.0/15", name: "Benchmarking", forwardable: "True", globallyReachable: "False" },
  {
    block: "198.51.100.0/24",
    name: "Documentation (TEST-NET-2)",
    forwardable: "False",
    globallyReachable: "False",
  },
  {
    block: "203.0.113.0/24",
    name: "Documentation (TEST-NET-3)",
    forwardable: "False",
    globallyReachable: "False",
  },
  { block: "240.0.0.0/4", name: "Reserved", forwardable: "False", globallyReachable: "False" },
  {
    block: "255.255.255.255/32",
    name: "Limited Broadcast",
    forwardable: "False",
    globallyReachable: "False",
  },
];

const IPV6_REGISTRY: RegistryRow[] = [
  { block: "::1/128", name: "Loopback Address", forwardable: "False", globallyReachable: "False" },
  {
    block: "::/128",
    name: "Unspecified Address",
    forwardable: "False",
    globallyReachable: "False",
  },
  {
    block: "::ffff:0:0/96",
    name: "IPv4-mapped Address",
    forwardable: "False",
    globallyReachable: "False",
  },
  {
    block: "64:ff9b::/96",
    name: "IPv4-IPv6 Translat.",
    forwardable: "True",
    globallyReachable: "True",
  },
  {
    block: "64:ff9b:1::/48",
    name: "IPv4-IPv6 Translat.",
    forwardable: "True",
    globallyReachable: "False",
  },
  {
    block: "100::/64",
    name: "Discard-Only Address Block",
    forwardable: "True",
    globallyReachable: "False",
  },
  {
    block: "100:0:0:1::/64",
    name: "Dummy IPv6 Prefix",
    forwardable: "False",
    globallyReachable: "False",
  },
  {
    block: "2001::/23",
    name: "IETF Protocol Assignments",
    forwardable: "False [1]",
    globallyReachable: "False [1]",
  },
  { block: "2001::/32", name: "TEREDO", forwardable: "True", globallyReachable: "N/A [2]" },
  {
    block: "2001:1::1/128",
    name: "Port Control Protocol Anycast",
    forwardable: "True",
    globallyReachable: "True",
  },
  {
    block: "2001:1::2/128",
    name: "Traversal Using Relays around NAT Anycast",
    forwardable: "True",
    globallyReachable: "True",
  },
  {
    block: "2001:1::3/128",
    name: "DNS-SD Service Registration Protocol Anycast",
    forwardable: "True",
    globallyReachable: "True",
  },
  { block: "2001:2::/48", name: "Benchmarking", forwardable: "True", globallyReachable: "False" },
  { block: "2001:3::/32", name: "AMT", forwardable: "True", globallyReachable: "True" },
  { block: "2001:4:112::/48", name: "AS112-v6", forwardable: "True", globallyReachable: "True" },
  {
    block: "2001:10::/28",
    name: "Deprecated (previously ORCHID)",
    forwardable: "",
    globallyReachable: "",
  },
  { block: "2001:20::/28", name: "ORCHIDv2", forwardable: "True", globallyReachable: "True" },
  {
    block: "2001:30::/28",
    name: "Drone Remote ID Protocol Entity Tags (DETs) Prefix",
    forwardable: "True",
    globallyReachable: "True",
  },
  {
    block: "2001:db8::/32",
    name: "Documentation",
    forwardable: "False",
    globallyReachable: "False",
  },
  { block: "2002::/16", name: "6to4", forwardable: "True", globallyReachable: "N/A [3]" },
  {
    block: "2620:4f:8000::/48",
    name: "Direct Delegation AS112 Service",
    forwardable: "True",
    globallyReachable: "True",
  },
  { block: "3fff::/20", name: "Documentation", forwardable: "False", globallyReachable: "False" },
  {
    block: "5f00::/16",
    name: "Segment Routing (SRv6) SIDs",
    forwardable: "True",
    globallyReachable: "False",
  },
  { block: "fc00::/7", name: "Unique-Local", forwardable: "True", globallyReachable: "False [4]" },
  {
    block: "fe80::/10",
    name: "Link-Local Unicast",
    forwardable: "False",
    globallyReachable: "False",
  },
];

const EXCEPTIONS: { cidr: string; reason: string }[] = [
  {
    cidr: "64:ff9b::/96",
    reason:
      "NAT64 well-known prefix: embedded IPv4 is checked via extraction in isBlockedAddress, not a wholesale block",
  },
  {
    cidr: "::ffff:0:0/96",
    reason:
      "IPv4-mapped: same extraction path as 64:ff9b::/96; a public embedded target must stay allowed",
  },
];

/** Public embedded literals that must stay allowed while the prefix remains an exception. */
const EXCEPTION_PROBE_ADDRS: Record<string, string[]> = {
  "64:ff9b::/96": ["64:ff9b::8.8.8.8"],
  "::ffff:0:0/96": ["::ffff:8.8.8.8"],
};

/** Forwardable and globally-reachable anycast and similar services (not required to block). */
const GLOBAL_SERVICES: { cidr: string; name: string }[] = [
  { cidr: "192.0.0.9/32", name: "Port Control Protocol Anycast" },
  { cidr: "192.0.0.10/32", name: "Traversal Using Relays around NAT Anycast" },
  { cidr: "192.31.196.0/24", name: "AS112-v4" },
  { cidr: "192.52.193.0/24", name: "AMT" },
  { cidr: "192.88.99.0/24", name: "Deprecated (6to4 Relay Anycast)" },
  { cidr: "192.175.48.0/24", name: "Direct Delegation AS112 Service" },
  { cidr: "2001::/32", name: "TEREDO" },
  { cidr: "2001:1::1/128", name: "Port Control Protocol Anycast" },
  { cidr: "2001:1::2/128", name: "Traversal Using Relays around NAT Anycast" },
  { cidr: "2001:1::3/128", name: "DNS-SD Service Registration Protocol Anycast" },
  { cidr: "2001:3::/32", name: "AMT" },
  { cidr: "2001:4:112::/48", name: "AS112-v6" },
  { cidr: "2001:10::/28", name: "Deprecated (previously ORCHID)" },
  { cidr: "2001:20::/28", name: "ORCHIDv2" },
  { cidr: "2001:30::/28", name: "Drone Remote ID Protocol Entity Tags (DETs) Prefix" },
  { cidr: "2002::/16", name: "6to4" },
  { cidr: "2620:4f:8000::/48", name: "Direct Delegation AS112 Service" },
];

const EXCEPTION_CIDRS = new Set(EXCEPTIONS.map((e) => e.cidr));

function isRegistryRequired(row: RegistryRow): boolean {
  return /^False/i.test(row.forwardable) || /^False/i.test(row.globallyReachable);
}

/** Parse an IANA special-purpose registry CSV export (untrusted data; never execute). */
function parseIanaRegistryCsv(text: string): RegistryRow[] {
  const rows = parseCsv(text);
  const header = rows[0];
  if (header === undefined) throw new Error("registry CSV is empty");
  if (
    header.length !== EXPECTED_IANA_COLUMNS.length ||
    !EXPECTED_IANA_COLUMNS.every((col, i) => header[i] === col)
  ) {
    throw new Error(`unexpected registry header: ${JSON.stringify(header)}`);
  }
  const bi = header.indexOf("Address Block");
  const ni = header.indexOf("Name");
  const fi = header.indexOf("Forwardable");
  const gi = header.indexOf("Globally Reachable");
  const out: RegistryRow[] = [];
  for (let r = 1; r < rows.length; r++) {
    const row = rows[r];
    if (row === undefined) {
      throw new Error(`registry row ${r}: missing`);
    }
    if (row.length !== header.length) {
      throw new Error(`registry row ${r}: ${row.join(",")}`);
    }
    const name = stripFootnotes(row[ni] ?? "");
    const forwardable = (row[fi] ?? "").trim();
    const globallyReachable = (row[gi] ?? "").trim();
    for (const block of splitBlocks(row[bi] ?? "")) {
      out.push({ block, name, forwardable, globallyReachable });
    }
  }
  return out;
}

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let i = 0;
  let field = "";
  let row: string[] = [];
  let inQ = false;
  const nl = "\n";
  const cr = "\r";
  while (i < text.length) {
    const c = text[i];
    if (inQ) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i += 2;
        continue;
      }
      if (c === '"') {
        inQ = false;
        i++;
        continue;
      }
      field += c;
      i++;
      continue;
    }
    if (c === '"') {
      inQ = true;
      i++;
      continue;
    }
    if (c === ",") {
      row.push(field);
      field = "";
      i++;
      continue;
    }
    if (c === nl || c === cr) {
      if (c === cr && text[i + 1] === nl) i++;
      row.push(field);
      field = "";
      if (row.some((x) => x !== "") || rows.length === 0) rows.push(row);
      row = [];
      i++;
      continue;
    }
    field += c;
    i++;
  }
  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function stripFootnotes(s: string): string {
  return s.replace(/\s*\[\d+\]/g, "").trim();
}

function splitBlocks(cell: string): string[] {
  return stripFootnotes(cell)
    .split(/,\s*/)
    .map((b) => b.trim())
    .filter(Boolean);
}

function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((n) => n > 255)) return null;
  return ((o[0]! << 24) | (o[1]! << 16) | (o[2]! << 8) | o[3]!) >>> 0;
}

function intToIpv4(n: number): string {
  n = n >>> 0;
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

function ipv6ToBigInt(ip: string): bigint {
  const bare = ip.includes("%") ? ip.slice(0, ip.indexOf("%")) : ip;
  const lastColon = bare.lastIndexOf(":");
  const tail = bare.slice(lastColon + 1);
  let text = bare;
  if (tail.includes(".")) {
    const v4 = ipv4ToInt(tail);
    if (v4 !== null) {
      const hi = (v4 >>> 16).toString(16);
      const lo = (v4 & 0xffff).toString(16);
      text = `${bare.slice(0, lastColon + 1)}${hi}:${lo}`;
    }
  }
  let groups: string[];
  if (text.includes("::")) {
    const [head, rest] = text.split("::");
    const headParts = head ? head.split(":") : [];
    const tailParts = rest ? rest.split(":") : [];
    const fill = 8 - headParts.length - tailParts.length;
    groups = [...headParts, ...Array<string>(fill).fill("0"), ...tailParts];
  } else {
    groups = text.split(":");
  }
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g || "0", 16)), 0n);
}

function bigIntToIpv6(val: bigint): string {
  const parts: string[] = [];
  for (let i = 0; i < 8; i++) {
    parts.push(((val >> BigInt((7 - i) * 16)) & 0xffffn).toString(16));
  }
  return parts.join(":");
}

function cidrBounds(cidr: string): [string, string, string] {
  const slash = cidr.indexOf("/");
  if (slash === -1) throw new Error(`not a CIDR: ${cidr}`);
  const addr = cidr.slice(0, slash);
  const bits = Number(cidr.slice(slash + 1));
  const fam = isIP(addr);
  if (fam === 0) throw new Error(`not an IP address: ${cidr}`);
  if (fam === 4) {
    const base = ipv4ToInt(addr);
    if (base === null) throw new Error(`bad IPv4 in ${cidr}`);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const first = (base & mask) >>> 0;
    const hostBits = 32 - bits;
    const last = bits === 32 ? first : (first | ((1 << hostBits) - 1)) >>> 0;
    const mid = hostBits === 0 ? first : (first + ((last - first) >>> 1)) >>> 0;
    return [intToIpv4(first), intToIpv4(mid), intToIpv4(last)];
  }
  const base = ipv6ToBigInt(addr);
  const max128 = (1n << 128n) - 1n;
  const mask = bits === 0 ? 0n : (~0n << BigInt(128 - bits)) & max128;
  const first = base & mask;
  const hostBits = 128 - bits;
  const last = bits === 128 ? first : first | ((1n << BigInt(hostBits)) - 1n);
  const mid = hostBits === 0 ? first : first + (last - first) / 2n;
  return [bigIntToIpv6(first), bigIntToIpv6(mid), bigIntToIpv6(last)];
}

function assertParseableCidr(block: string): void {
  cidrBounds(block);
}

function requiredRows(registry: RegistryRow[]): RegistryRow[] {
  return registry.filter((row) => isRegistryRequired(row) && !EXCEPTION_CIDRS.has(row.block));
}

const NO_EXTRA: readonly never[] = [];

describe("IANA special-purpose registry snapshot", () => {
  it("parsed to a sensible row count with parseable blocks and registry cells", () => {
    for (const registry of [IPV4_REGISTRY, IPV6_REGISTRY]) {
      expect(registry.length).toBeGreaterThanOrEqual(10);
      for (const row of registry) {
        assertParseableCidr(row.block);
        if (row.forwardable === "" && row.globallyReachable === "") continue;
        expect(row.forwardable.length).toBeGreaterThan(0);
        expect(row.globallyReachable.length).toBeGreaterThan(0);
      }
    }
  });

  it("fails when a registry row has an unexpected column layout", () => {
    expect(() => parseIanaRegistryCsv("Address Block,Name\n10.0.0.0/8,Private")).toThrow(
      /unexpected registry header/,
    );
    expect(() =>
      parseIanaRegistryCsv(
        `${EXPECTED_IANA_COLUMNS.join(",")}\n10.0.0.0/8,Private,[RFC1918],1996-02,N/A,True,True,True,False,False`,
      ),
    ).not.toThrow();
    expect(() =>
      parseIanaRegistryCsv(
        `${EXPECTED_IANA_COLUMNS.join(",")}\n10.0.0.0/8,Private,[RFC1918],1996-02,N/A,True,True,True,False`,
      ),
    ).toThrow(/registry row 1:/);
  });

  it("accounts for every non-required row in GLOBAL_SERVICES", () => {
    const globalSet = new Set(GLOBAL_SERVICES.map((g) => `${g.cidr}\0${g.name}`));
    for (const registry of [...IPV4_REGISTRY, ...IPV6_REGISTRY]) {
      if (isRegistryRequired(registry) || EXCEPTION_CIDRS.has(registry.block)) continue;
      const key = `${registry.block}\0${registry.name}`;
      expect(
        globalSet.has(key),
        `missing GLOBAL_SERVICES entry for ${registry.block} (${registry.name})`,
      ).toBe(true);
    }
  });
});

describe("isBlockedAddress vs IANA required ranges", () => {
  const cases = [
    ...requiredRows(IPV4_REGISTRY).map((row) => ({ ...row, family: "IPv4" as const })),
    ...requiredRows(IPV6_REGISTRY).map((row) => ({ ...row, family: "IPv6" as const })),
  ];

  it.each(cases)("blocks first, middle, and last of $family $name ($block)", (row) => {
    const [first, middle, last] = cidrBounds(row.block);
    for (const addr of [first, middle, last]) {
      expect(isBlockedAddress(addr, NO_EXTRA), `${row.name} ${row.block} @ ${addr}`).toBe(true);
    }
  });

  it.each(EXCEPTIONS)(
    "keeps exception $cidr reachable for at least one probe address ($reason)",
    ({ cidr }) => {
      const probes = EXCEPTION_PROBE_ADDRS[cidr];
      expect(probes?.length, `missing probes for exception ${cidr}`).toBeGreaterThan(0);
      const blocked = probes!.map((addr) => isBlockedAddress(addr, NO_EXTRA));
      expect(
        blocked.some((b) => !b),
        "remove this stale exception",
      ).toBe(true);
    },
  );
});
