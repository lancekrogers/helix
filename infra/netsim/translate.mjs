/** @typedef {'off' | 'deny-list-only' | 'enforce'} NsgMode */
/** @typedef {'pinned' | 'unpinned'} PePinning */

/**
 * @param {object} json
 * @returns {object[]}
 */
export function loadRules(json) {
  return json.rules;
}

/**
 * @param {object[]} rules
 * @param {NsgMode} mode
 * @param {PePinning} pinning
 * @returns {object[]}
 */
export function activeRules(rules, mode, pinning) {
  if (mode === "off") {
    return [];
  }
  return rules.filter((rule) => {
    if (!rule.modes.includes(mode)) {
      return false;
    }
    if (rule.pePinning !== undefined) {
      return rule.pePinning === pinning;
    }
    return true;
  });
}

/**
 * @param {object} rule
 * @param {{ refs: Record<string, string>, tags: Record<string, string>, allowedPorts: string[] }} ctx
 */
export function resolveRule(rule, ctx) {
  const dst = rule.destinationPrefixes.map((p) => ctx.refs[p] ?? ctx.tags[p] ?? p);
  const ports = rule.destinationPorts.flatMap((p) =>
    p === "$allowedPorts" ? ctx.allowedPorts : [p],
  );
  return { ...rule, dst, ports };
}

/**
 * Build iptables argument lists for OUTPUT (outbound NSG rows only).
 *
 * @param {object[]} rules full rule table
 * @param {NsgMode} mode
 * @param {{ refs: Record<string, string>, tags: Record<string, string>, allowedPorts: string[] }} ctx
 * @param {PePinning} [pinning='pinned']
 * @returns {string[][]}
 */
export function toIptables(rules, mode, ctx, pinning = "pinned") {
  const lines = [
    ["-F", "OUTPUT"],
    ["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
  ];
  lines.push([
    "-A",
    "OUTPUT",
    "-m",
    "conntrack",
    "--ctstate",
    "ESTABLISHED,RELATED",
    "-j",
    "ACCEPT",
  ]);

  // Azure host-node paths are exempt from prefix-based NSG rules:
  // https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16
  // https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview
  lines.push(["-A", "OUTPUT", "-p", "tcp", "-d", "168.63.129.16", "--dport", "53", "-j", "ACCEPT"]);
  lines.push(["-A", "OUTPUT", "-p", "udp", "-d", "168.63.129.16", "--dport", "53", "-j", "ACCEPT"]);
  lines.push(["-A", "OUTPUT", "-p", "tcp", "-d", "168.63.129.16", "--dport", "80", "-j", "ACCEPT"]);
  lines.push([
    "-A",
    "OUTPUT",
    "-p",
    "tcp",
    "-d",
    "168.63.129.16",
    "--dport",
    "32526",
    "-j",
    "ACCEPT",
  ]);
  lines.push(["-A", "OUTPUT", "-d", "169.254.169.254", "-j", "ACCEPT"]);

  const outbound = activeRules(rules, mode, pinning)
    .filter((r) => r.direction === "Outbound")
    .sort((a, b) => a.priority - b.priority);

  for (const rule of outbound) {
    const { dst, ports, access, protocol } = resolveRule(rule, ctx);
    const target = access === "Allow" ? "ACCEPT" : "DROP";
    const protoSpecs = expandProtocols(protocol, ports);
    for (const prefix of dst) {
      for (const proto of protoSpecs) {
        const portList =
          proto.ports.length === 0
            ? ports.length === 1 && ports[0] === "*"
              ? []
              : ports
            : proto.ports;
        if (portList.length === 0) {
          lines.push(buildRuleLine(prefix, proto, null, target));
        } else {
          for (const port of portList) {
            lines.push(buildRuleLine(prefix, proto, port, target));
          }
        }
      }
    }
  }

  lines.push(["-A", "OUTPUT", "-j", "ACCEPT"]);
  return lines;
}

/**
 * @param {string} protocol
 * @param {string[]} ports
 * @returns {{ proto: string | null, ports: string[] }[]}
 */
function expandProtocols(protocol, ports) {
  const anyPort = ports.length === 1 && ports[0] === "*";
  if (protocol === "Tcp") {
    return [{ proto: "tcp", ports: anyPort ? [] : ports }];
  }
  if (protocol === "Udp") {
    return [{ proto: "udp", ports: anyPort ? [] : ports }];
  }
  if (protocol === "*") {
    if (anyPort) {
      return [{ proto: null, ports: [] }];
    }
    return [
      { proto: "tcp", ports },
      { proto: "udp", ports },
    ];
  }
  throw new Error(`unknown protocol: ${protocol}`);
}

/**
 * @param {string} dstCidr
 * @param {{ proto: string | null, ports: string[] }} spec
 * @param {string | null} port
 * @param {'ACCEPT' | 'DROP'} target
 */
function buildRuleLine(dstCidr, spec, port, target) {
  const args = ["-A", "OUTPUT"];
  if (spec.proto) {
    args.push("-p", spec.proto);
  }
  if (dstCidr !== "*") {
    args.push("-d", dstCidr);
  }
  if (port && port !== "*") {
    const dport = port.includes("-") ? port.replace("-", ":") : port;
    args.push("--dport", dport);
  }
  args.push("-j", target);
  return args;
}

/**
 * @param {object[]} rules
 * @param {string} spec
 * @returns {object[]}
 */
export function applyBreak(rules, spec) {
  const [op, ...rest] = spec.split(":");
  if (op === "remove") {
    const name = rest.join(":");
    const idx = rules.findIndex((r) => r.name === name);
    if (idx === -1) {
      throw new Error(`unknown rule name: ${name}`);
    }
    return rules.filter((_, i) => i !== idx);
  }
  if (op === "renumber") {
    const [name, priorityStr] = rest;
    const priority = Number(priorityStr);
    if (!name || !Number.isInteger(priority)) {
      throw new Error(`invalid renumber spec: ${spec}`);
    }
    const idx = rules.findIndex((r) => r.name === name);
    if (idx === -1) {
      throw new Error(`unknown rule name: ${name}`);
    }
    return rules.map((r, i) => (i === idx ? { ...r, priority } : r));
  }
  throw new Error(`unknown break op: ${op}`);
}
