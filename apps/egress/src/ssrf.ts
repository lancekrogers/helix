import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import { Agent, buildConnector } from "undici";

/**
 * SSRF hardening (fetch-proxy design §6). An outbound proxy driven by untrusted
 * apps is an SSRF engine if built naively — the Capital One IMDS vector. The
 * controls here are the network-layer belt to the edge's application-layer
 * suspenders: resolve the host ourselves, refuse private/link-local/metadata
 * targets, and pin the connection to the validated address so a DNS rebind
 * between check and connect can't slip through.
 *
 * `allowPrivate` is a deliberate **test/dev** seam: integration tests point the
 * proxy at a loopback upstream, and dev may too. It is false in prod and in the
 * adversarial suite, where 127.0.0.1 / 169.254.169.254 must be refused.
 */

export class SsrfBlockedError extends Error {
  constructor(reason: string) {
    super(`egress refused target: ${reason}`);
    this.name = "SsrfBlockedError";
  }
}

/** Parse an IPv4 dotted quad to its 32-bit integer, or null if not IPv4. */
function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((n) => n > 255)) return null;
  return ((o[0]! << 24) | (o[1]! << 16) | (o[2]! << 8) | o[3]!) >>> 0;
}

function inV4Cidr(ipInt: number, base: string, bits: number): boolean {
  const baseInt = ipv4ToInt(base)!;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

/** IPv4 ranges that must never be reachable through the proxy. */
const V4_BLOCKED: [string, number][] = [
  ["0.0.0.0", 8], // "this host"
  ["10.0.0.0", 8], // RFC 1918
  ["100.64.0.0", 10], // CGNAT
  ["127.0.0.0", 8], // loopback
  ["168.63.129.16", 32], // Azure virtual public IP: wire server, platform DNS, health probes
  ["169.254.0.0", 16], // link-local — includes 169.254.169.254 (IMDS)
  ["172.16.0.0", 12], // RFC 1918
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // TEST-NET-1 (documentation)
  ["192.88.99.0", 24], // deprecated 6to4 relay anycast (v6 2002::/16 is already blocked)
  ["192.168.0.0", 16], // RFC 1918
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // TEST-NET-2 (documentation)
  ["203.0.113.0", 24], // TEST-NET-3 (documentation)
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved
];

/** True if a 32-bit IPv4 integer falls in any blocked v4 range. */
function isBlockedV4Int(ipInt: number): boolean {
  return V4_BLOCKED.some(([base, bits]) => inV4Cidr(ipInt, base, bits));
}

const MAX128 = (1n << 128n) - 1n;

/**
 * Expand a format-valid IPv6 literal to its 128-bit value. Precondition: the
 * caller has already checked `isIP(ip) === 6`, so we only expand — we do not
 * re-validate. `isIP` accepts a `%zone` suffix (only ever on non-global scopes,
 * which the blocklist catches regardless), so strip it before parsing.
 *
 * A textual embedded-IPv4 tail (`::a.b.c.d`, `::ffff:a.b.c.d`) is folded into two
 * hex groups via the existing {@link ipv4ToInt}, keeping all v4 parsing in one
 * place. Hex forms (`::ffff:7f00:1`) need no special handling — the WHATWG URL
 * parser normalizes dotted-mapped literals to hex anyway, so hex is the form that
 * actually arrives.
 */
function ipv6ToBigInt(ip: string): bigint {
  const bare = ip.includes("%") ? ip.slice(0, ip.indexOf("%")) : ip;

  // Fold a trailing dotted-quad (the last colon-group containing a ".") into hex.
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

function inV6Cidr(val: bigint, base: bigint, bits: number): boolean {
  const mask = bits === 0 ? 0n : (~0n << BigInt(128 - bits)) & MAX128;
  return (val & mask) === (base & mask);
}

/**
 * IPv6 ranges (IANA IPv6 Special-Purpose Registry) that must never be reachable.
 * Embedded-IPv4 forms (`::ffff:/96` mapped, `64:ff9b::/96` NAT64, `::ffff:0:0:0/96`
 * translated, `::/96` compat) are handled by extraction in {@link isBlockedAddress},
 * not here, so a *public*
 * embedded target stays allowed while an internal one is blocked.
 */
const V6_BLOCKED: [string, number][] = [
  ["::1", 128], // loopback (also caught by ::/96 extraction — kept for clarity)
  ["::", 128], // unspecified (ditto)
  ["fe80::", 10], // link-local — fixes the old `fe80`-prefix miss (e.g. fea0::1)
  ["fec0::", 10], // site-local (deprecated, RFC 3879)
  ["fc00::", 7], // unique-local (ULA)
  ["64:ff9b:1::", 48], // NAT64 local-use (RFC 8215) — block wholesale
  ["100::", 64], // discard-only (RFC 6666)
  ["2001:db8::", 32], // documentation
  ["2002::", 16], // 6to4 (deprecated, RFC 7526)
  ["2001::", 23], // Teredo / ORCHIDv2 / benchmarking (defense-in-depth)
  ["3fff::", 20], // documentation (RFC 9637)
  ["5f00::", 16], // segment-routing SIDs (RFC 9602)
  ["ff00::", 8], // multicast (parity with v4 224.0.0.0/4)
];

// Parse the blocklist bases to their numeric values once, at module load.
const V6_BLOCKED_NUM: [bigint, number][] = V6_BLOCKED.map(([base, bits]) => [
  ipv6ToBigInt(base),
  bits,
]);

const V6_MAPPED = ipv6ToBigInt("::ffff:0:0"); // ::ffff:0:0/96
const V6_NAT64 = ipv6ToBigInt("64:ff9b::"); // 64:ff9b::/96
const V6_TRANSLATED = ipv6ToBigInt("::ffff:0:0:0"); // ::ffff:0:0:0/96 IPv4-translated (SIIT)

/** True if the resolved address is one we must never connect to. */
export function isBlockedAddress(ip: string): boolean {
  const v4 = ipv4ToInt(ip);
  if (v4 !== null) return isBlockedV4Int(v4);

  if (isIP(ip) === 6) {
    const val = ipv6ToBigInt(ip);
    // Extract the embedded IPv4 and re-check it, regardless of hex/dotted notation.
    if (inV6Cidr(val, V6_MAPPED, 96)) return isBlockedV4Int(Number(val & 0xffffffffn)); // ::ffff:a.b.c.d
    if (inV6Cidr(val, V6_NAT64, 96)) return isBlockedV4Int(Number(val & 0xffffffffn)); // 64:ff9b::a.b.c.d
    if (inV6Cidr(val, V6_TRANSLATED, 96)) return isBlockedV4Int(Number(val & 0xffffffffn)); // ::ffff:0:a.b.c.d
    if (val >> 32n === 0n) return isBlockedV4Int(Number(val)); // ::a.b.c.d compat (covers ::, ::1)
    return V6_BLOCKED_NUM.some(([base, bits]) => inV6Cidr(val, base, bits));
  }
  // Not a recognizable IP literal — refuse rather than guess.
  return true;
}

export interface ValidatedTarget {
  /** The pinned address to connect to (defeats rebind). */
  address: string;
  family: 4 | 6;
}

/**
 * Resolve a hostname and validate **every** returned address, returning the
 * validated set in resolver order. An IP literal is validated directly.
 * Throws {@link SsrfBlockedError} if anything resolves into a blocked range —
 * refusing the whole host if any address is blocked, so a dual-A-record trick
 * can't pick the public one for the check and the private one for the connect.
 */
export async function resolveAndValidate(
  hostname: string,
  allowPrivate: boolean,
): Promise<ValidatedTarget[]> {
  // URL.hostname keeps IPv6 brackets ("[::1]"); strip them for isIP/lookup.
  const host =
    hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  const literal = isIP(host);
  if (literal) {
    if (!allowPrivate && isBlockedAddress(host)) {
      throw new SsrfBlockedError(`${host} is a blocked address`);
    }
    return [{ address: host, family: literal === 6 ? 6 : 4 }];
  }

  const addrs = await dnsLookup(host, { all: true });
  if (addrs.length === 0) throw new SsrfBlockedError(`${host} did not resolve`);
  if (!allowPrivate) {
    for (const a of addrs) {
      if (isBlockedAddress(a.address)) {
        throw new SsrfBlockedError(`${hostname} resolves to blocked ${a.address}`);
      }
    }
  }
  return addrs.map((a) => ({ address: a.address, family: a.family === 6 ? 6 : 4 }));
}

/**
 * A shared connector that resolves + validates the target host and **pins the
 * socket to the validated IP** on every new connection, then hands off to
 * undici's default connector — so one long-lived {@link Agent} keeps connection
 * pooling (keep-alive across requests to the same origin) without losing the
 * SSRF IP-pin (ADR-0005 perf note). We dial the real origin (undici pools by
 * origin and sets SNI/Host from it); the connector only rewrites the socket
 * target to the validated IP.
 *
 * Validation runs per *new* socket. A pooled/keep-alive socket is already bonded
 * to a validated IP, so reuse can only ever reach that same address — a DNS
 * rebind between requests cannot redirect a live connection, and the next fresh
 * connection re-resolves and re-validates. `resolveAndValidate` throws
 * {@link SsrfBlockedError} for a blocked or unresolvable host; undici propagates
 * it verbatim to the `request()` rejection, where the handler maps it to a 403
 * `blocked` (preserving the old upfront-check semantics).
 *
 * This is the ONE definition of the pinned transport: the fetch-proxy's
 * dispatcher and the exchange operation's
 * `customFetch` adapter both build on it, so the SSRF controls survive every
 * outbound hop this plane makes — an OAuth library's own fetch would not
 * inherit them.
 */
export function makeValidatingConnector(
  allowPrivate: boolean,
  timeoutMs: number,
): buildConnector.connector {
  const base = buildConnector({ timeout: timeoutMs });
  return function connect(opts, callback): void {
    resolveAndValidate(opts.hostname, allowPrivate).then(
      (targets) => {
        // Dial the validated addresses in resolver order; the first that
        // CONNECTS wins. A host legitimately publishes ::1 and 127.0.0.1 while
        // the service listens on one family, and a resolver that orders the
        // other family first made every call to addrs[0] dead (measured:
        // ECONNREFUSED ::1 on GitHub's runners against an IPv4-only dev
        // fixture). undici's own happy-eyeballs cannot help here — the pin
        // hands it a single IP literal — so the fallback is ours. Every
        // candidate was validated above, so whichever socket wins is bonded to
        // a checked address; a live connection is never re-pointed (the
        // anti-rebind property is per-connection, and the next fresh
        // connection re-resolves and re-validates).
        let index = 0;
        const attempt = (lastErr: Error): void => {
          const target = targets[index];
          index += 1;
          if (target === undefined) {
            // Unreachable: resolveAndValidate refuses an empty resolution.
            callback(lastErr, null);
            return;
          }
          // Dial the validated IP literal; keep SNI + cert identity on the real
          // hostname. undici leaves `servername` unset for the connector, so it
          // must be pinned here exactly as the old per-request `connect.servername`
          // did — otherwise the default connector would derive SNI from the IP.
          base(
            { ...opts, hostname: target.address, servername: opts.servername ?? opts.hostname },
            (err, socket) => {
              // undici's failure path calls back with the error and NO socket —
              // sometimes one-arg (socket undefined), which is why the guard is
              // loose rather than `socket === null`.
              if (err !== null && err !== undefined) {
                attempt(err instanceof Error ? err : new Error(String(err)));
                return;
              }
              if (socket === null || socket === undefined) {
                attempt(new Error(`${target.address}: dial returned no socket`));
                return;
              }
              callback(null, socket);
            },
          );
        };
        attempt(new Error(`${opts.hostname}: no validated address connected`));
      },
      (err: unknown) => callback(err instanceof Error ? err : new Error(String(err)), null),
    );
  };
}

/** An {@link Agent} over {@link makeValidatingConnector} — the pinned dispatcher. */
export function makePinnedDispatcher(allowPrivate: boolean, timeoutMs: number): Agent {
  return new Agent({
    connect: makeValidatingConnector(allowPrivate, timeoutMs),
  });
}
