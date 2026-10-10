import { describe, it, expect, vi, beforeEach } from "vitest";

// First DNS mock in the repo: lets us exercise the resolveAndValidate AAAA-rebind
// path (the real SSRF exploit vector) without a live resolver. Hoisted by vitest.
vi.mock("node:dns/promises", () => ({ lookup: vi.fn() }));

import type { LookupAddress } from "node:dns";
import type { AddressInfo } from "node:net";
import { lookup } from "node:dns/promises";
import {
  isBlockedAddress,
  makeValidatingConnector,
  resolveAndValidate,
  SsrfBlockedError,
} from "./ssrf.js";

const mockLookup = vi.mocked(lookup);

// resolveAndValidate calls lookup(host, { all: true }), which returns an array;
// vi.mocked resolves to the single-address overload, so cast the array once here.
function resolveTo(addrs: LookupAddress[]): void {
  mockLookup.mockResolvedValue(addrs as unknown as LookupAddress);
}

function embed(form: "mapped" | "nat64" | "compat" | "translated", v4: string): string {
  const [a, b, c, d] = v4.split(".").map(Number) as [number, number, number, number];
  const hi = ((a << 8) | b).toString(16);
  const lo = ((c << 8) | d).toString(16);
  const prefix = { mapped: "::ffff:", nat64: "64:ff9b::", compat: "::", translated: "::ffff:0:" }[
    form
  ];
  return `${prefix}${hi}:${lo}`;
}

describe("isBlockedAddress — IPv6 forms now blocked", () => {
  // Every row here returned `false` (treated as public) under the old
  // prefix-matching implementation — the issue #2 bypass table plus edges.
  it.each([
    "fe80::1", // link-local
    "fea0::1", // link-local — the /10 the old `fe80` prefix missed
    "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", // upper edge of fe80::/10
    "fec0::1", // site-local (deprecated)
    "fc00::1", // ULA
    "fd00::1", // ULA
    "fdff:ffff::1", // ULA upper
    "::1", // loopback
    "::", // unspecified
    "::7f00:1", // ::127.0.0.1 (v4-compatible loopback, hex)
    "::ffff:7f00:1", // 127.0.0.1 (v4-mapped, hex — the form URL parsing produces)
    "::ffff:a9fe:a9fe", // 169.254.169.254 (v4-mapped IMDS, hex)
    "64:ff9b::a9fe:a9fe", // NAT64-embedded 169.254.169.254 (IMDS)
    "64:ff9b:1::a9fe:a9fe", // NAT64 local-use /48
    "2002:7f00:1::1", // 6to4-embedded 127.0.0.1
    "2002:a9fe:a9fe::1", // 6to4-embedded 169.254.169.254
    "2001:0:0::1", // Teredo (2001::/23)
    "100::1", // discard-only
    "2001:db8::1", // documentation
    "ff02::1", // multicast
  ])("blocks %s", (ip) => {
    expect(isBlockedAddress(ip)).toBe(true);
  });
});

describe("isBlockedAddress — IPv6 public targets allowed", () => {
  it.each([
    "2606:4700:4700::1111", // Cloudflare DNS
    "2001:4860:4860::8888", // Google DNS
    "2a00:1450:4009:80f::200e", // Google
    "::ffff:8.8.8.8", // public v4-mapped — extraction allows it
    "64:ff9b::8.8.8.8", // NAT64-to-public — extraction allows it
  ])("allows %s", (ip) => {
    expect(isBlockedAddress(ip)).toBe(false);
  });
});

describe("isBlockedAddress — zone identifiers", () => {
  it("strips the %zone and still classifies the base scope", () => {
    expect(isBlockedAddress("fe80::1%eth0")).toBe(true);
  });
});

describe("isBlockedAddress — new IPv4 ranges (boundaries)", () => {
  it.each([
    ["168.63.129.16/32", "168.63.129.16", "168.63.129.16", "168.63.129.15", "168.63.129.17"],
    ["192.0.2.0/24", "192.0.2.0", "192.0.2.255", "192.0.1.255", "192.0.3.0"],
    ["198.51.100.0/24", "198.51.100.0", "198.51.100.255", "198.51.99.255", "198.51.101.0"],
    ["203.0.113.0/24", "203.0.113.0", "203.0.113.255", "203.0.112.255", "203.0.114.0"],
    ["192.88.99.0/24", "192.88.99.0", "192.88.99.255", "192.88.98.255", "192.88.100.0"],
  ])("blocks first and last of %s", (_range, first, last) => {
    expect(isBlockedAddress(first)).toBe(true);
    expect(isBlockedAddress(last)).toBe(true);
  });

  it.each([
    ["168.63.129.16/32", "168.63.129.15", "168.63.129.17"],
    ["192.0.2.0/24", "192.0.1.255", "192.0.3.0"],
    ["198.51.100.0/24", "198.51.99.255", "198.51.101.0"],
    ["203.0.113.0/24", "203.0.112.255", "203.0.114.0"],
    ["192.88.99.0/24", "192.88.98.255", "192.88.100.0"],
  ])("allows the neighbors of %s", (_range, below, above) => {
    expect(isBlockedAddress(below)).toBe(false);
    expect(isBlockedAddress(above)).toBe(false);
  });
});

describe("isBlockedAddress — new ranges through every embedded form", () => {
  const rangeEndpoints = [
    ["168.63.129.16/32", "168.63.129.16"],
    ["192.0.2.0/24", "192.0.2.0", "192.0.2.255"],
    ["198.51.100.0/24", "198.51.100.0", "198.51.100.255"],
    ["203.0.113.0/24", "203.0.113.0", "203.0.113.255"],
    ["192.88.99.0/24", "192.88.99.0", "192.88.99.255"],
  ] as const;

  for (const row of rangeEndpoints) {
    const [label, ...addrs] = row;
    for (const v4 of addrs) {
      for (const form of ["mapped", "nat64", "compat", "translated"] as const) {
        it(`blocks ${label} endpoint ${v4} as ${form}`, () => {
          expect(isBlockedAddress(embed(form, v4))).toBe(true);
        });
      }
    }
  }

  it.each(["::ffff:a83f:8110", "64:ff9b::a83f:8110", "::a83f:8110", "::ffff:0:a83f:8110"])(
    "blocks literal Azure platform spelling %s",
    (ip) => {
      expect(isBlockedAddress(ip)).toBe(true);
    },
  );

  it.each([embed("mapped", "168.63.129.17"), embed("translated", "8.8.8.8")])(
    "allows public embedded %s",
    (ip) => {
      expect(isBlockedAddress(ip)).toBe(false);
    },
  );
});

describe("isBlockedAddress — new IPv6 ranges", () => {
  it.each([
    ["3fff::/20", "3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"],
    ["5f00::/16", "5f00::", "5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
  ])("blocks first and last of %s", (_range, first, last) => {
    expect(isBlockedAddress(first)).toBe(true);
    expect(isBlockedAddress(last)).toBe(true);
  });

  it.each([
    ["3fff::/20", "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "3fff:1000::"],
    ["5f00::/16", "5eff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "5f01::"],
  ])("allows the neighbors of %s", (_range, below, above) => {
    expect(isBlockedAddress(below)).toBe(false);
    expect(isBlockedAddress(above)).toBe(false);
  });
});

describe("isBlockedAddress — IPv4 ranges (regression)", () => {
  it.each([
    "169.254.169.254", // IMDS
    "127.0.0.1",
    "10.0.0.5",
    "192.168.1.1",
    "172.16.0.1",
    "100.64.0.1",
    "0.0.0.0",
  ])("blocks %s", (ip) => {
    expect(isBlockedAddress(ip)).toBe(true);
  });

  it.each(["8.8.8.8", "1.1.1.1"])("allows %s", (ip) => {
    expect(isBlockedAddress(ip)).toBe(false);
  });
});

describe("IPv4 alternate literals are normalized by the URL parser, not isBlockedAddress", () => {
  // The decimal/hex/octal/short IPv4 forms raised in review never reach
  // isBlockedAddress in raw form: the WHATWG URL parser normalizes them to the
  // dotted quad first. This proves *where* the safety comes from.
  it.each([
    "http://2130706433/", // decimal
    "http://0x7f000001/", // hex
    "http://127.1/", // short form
    "http://0177.0.0.1/", // octal
  ])("URL parser normalizes %s to 127.0.0.1", (url) => {
    const { hostname } = new URL(url);
    expect(hostname).toBe("127.0.0.1");
    expect(isBlockedAddress(hostname)).toBe(true);
  });

  it("defensively refuses an un-normalized bare-integer literal", () => {
    // Not the real defense (the URL layer is) — but a raw string that is neither
    // a dotted quad nor a valid IP literal hits the refuse-unrecognized branch.
    expect(isBlockedAddress("2130706433")).toBe(true);
  });
});

describe("resolveAndValidate — DNS AAAA rebind (mocked lookup)", () => {
  beforeEach(() => mockLookup.mockReset());

  it("rejects a host whose AAAA is NAT64-embedded IMDS", async () => {
    resolveTo([{ address: "64:ff9b::a9fe:a9fe", family: 6 }]);
    await expect(resolveAndValidate("api.partner.com", false)).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it("rejects a host whose AAAA is a hex v4-mapped loopback", async () => {
    resolveTo([{ address: "::ffff:7f00:1", family: 6 }]);
    await expect(resolveAndValidate("api.partner.com", false)).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it("resolves a genuinely public AAAA", async () => {
    resolveTo([{ address: "2606:4700:4700::1111", family: 6 }]);
    await expect(resolveAndValidate("api.partner.com", false)).resolves.toEqual([
      { address: "2606:4700:4700::1111", family: 6 },
    ]);
  });

  it("returns the full validated set in resolver order (the connector dials them in turn)", async () => {
    resolveTo([
      { address: "2606:4700:4700::1111", family: 6 },
      { address: "8.8.8.8", family: 4 },
    ]);
    await expect(resolveAndValidate("api.partner.com", false)).resolves.toEqual([
      { address: "2606:4700:4700::1111", family: 6 },
      { address: "8.8.8.8", family: 4 },
    ]);
  });

  it("rejects the whole host when any address is blocked (dual-record)", async () => {
    resolveTo([
      { address: "2606:4700:4700::1111", family: 6 },
      { address: "::ffff:7f00:1", family: 6 },
    ]);
    await expect(resolveAndValidate("api.partner.com", false)).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it("rejects a host whose A record is the Azure platform address", async () => {
    resolveTo([{ address: "168.63.129.16", family: 4 }]);
    await expect(resolveAndValidate("api.partner.com", false)).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it("rejects the whole host when one A record is the Azure platform address (dual-record)", async () => {
    resolveTo([
      { address: "8.8.8.8", family: 4 },
      { address: "168.63.129.16", family: 4 },
    ]);
    await expect(resolveAndValidate("api.partner.com", false)).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it("rejects a host whose AAAA is IPv4-translated Azure platform", async () => {
    resolveTo([{ address: "::ffff:0:a83f:8110", family: 6 }]);
    await expect(resolveAndValidate("api.partner.com", false)).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
  });

  it("bypasses validation under the allowPrivate dev/test seam", async () => {
    resolveTo([{ address: "64:ff9b::a9fe:a9fe", family: 6 }]);
    await expect(resolveAndValidate("api.partner.com", true)).resolves.toEqual([
      { address: "64:ff9b::a9fe:a9fe", family: 6 },
    ]);
  });
});

describe("resolveAndValidate — IP-literal branch", () => {
  beforeEach(() => mockLookup.mockReset());

  it("strips brackets and blocks a mapped-loopback literal without a DNS lookup", async () => {
    await expect(resolveAndValidate("[::ffff:7f00:1]", false)).rejects.toBeInstanceOf(
      SsrfBlockedError,
    );
    expect(mockLookup).not.toHaveBeenCalled();
  });
});

describe("makeValidatingConnector — dial the validated addresses in order", () => {
  beforeEach(() => mockLookup.mockReset());

  // The CI-run regression, end to end at the connector layer: the runner's
  // resolver ordered `localhost` ::1-first, the fixture listened on IPv4 only,
  // and the old pin-to-addrs[0] connector handed undici one dead address —
  // `connect ECONNREFUSED ::1` with no fallback (undici cannot happy-eyeball a
  // single literal). The connector must dial the validated addresses in turn.
  it("falls back to the next validated address when the first refuses", async () => {
    const net = await import("node:net");
    const server = net.createServer((socket) => socket.end());
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const port = (server.address() as AddressInfo).port;
    try {
      resolveTo([
        { address: "::1", family: 6 }, // nothing listens here
        { address: "127.0.0.1", family: 4 }, // the real listener
      ]);
      const connector = makeValidatingConnector(true, 5_000);
      await new Promise<void>((resolve, reject) => {
        connector(
          {
            hostname: "localhost",
            servername: undefined,
            port: String(port),
            protocol: "http:",
          } as Parameters<ReturnType<typeof makeValidatingConnector>>[0],
          (err, socket) => {
            if (err !== null || socket === null) {
              reject(err ?? new Error("no socket"));
              return;
            }
            try {
              expect(socket.remoteAddress).toBe("127.0.0.1");
              socket.destroy();
              resolve();
            } catch (e) {
              reject(e as Error);
            }
          },
        );
      });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("reports the last dial error when every validated address refuses", async () => {
    // A port with no listener on either family: the OS assigns nobody.
    const net = await import("node:net");
    const gate = net.createServer();
    await new Promise<void>((resolve) => gate.listen(0, "127.0.0.1", () => resolve()));
    const deadPort = (gate.address() as AddressInfo).port;
    await new Promise<void>((resolve) => gate.close(() => resolve()));
    resolveTo([
      { address: "::1", family: 6 },
      { address: "127.0.0.1", family: 4 },
    ]);
    const connector = makeValidatingConnector(true, 5_000);
    await new Promise<void>((resolve, reject) => {
      connector(
        {
          hostname: "localhost",
          servername: undefined,
          port: String(deadPort),
          protocol: "http:",
        } as Parameters<ReturnType<typeof makeValidatingConnector>>[0],
        (err, socket) => {
          try {
            expect(err).toBeInstanceOf(Error);
            expect(socket).toBeNull();
            resolve();
          } catch (e) {
            reject(e as Error);
          }
        },
      );
    });
  }, 30_000);
});
