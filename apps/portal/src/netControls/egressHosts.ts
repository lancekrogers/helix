import { CapabilitiesSchema } from "@azx-pbc/shared";
import type { PrismaClient } from "../db/client.js";

export interface HostNeed {
  host: string;
  sources: string[];
}

export interface HostDiffRow extends HostNeed {
  listed: boolean;
}

export interface AppCapabilitiesRow {
  slug: string;
  capabilities: unknown;
}

export interface ProviderRow {
  ref: string;
  tokenEndpoint: string;
  apiOrigins: string[];
}

export interface HostsFromAppsResult {
  hosts: { host: string; source: string }[];
  unparseable: { slug: string }[];
}

/** Strip scheme, path, and port; firewall rules in this task are 80/443 only. */
export function hostFromUrl(url: string): string {
  return new URL(url).hostname.toLowerCase();
}

export function hostsFromApps(rows: AppCapabilitiesRow[]): HostsFromAppsResult {
  const hosts: { host: string; source: string }[] = [];
  const unparseable: { slug: string }[] = [];

  for (const row of rows) {
    const parsed = CapabilitiesSchema.safeParse(row.capabilities ?? {});
    if (!parsed.success) {
      unparseable.push({ slug: row.slug });
      continue;
    }
    const origins = parsed.data.fetch?.origins ?? [];
    for (const entry of origins) {
      hosts.push({
        host: hostFromUrl(entry.origin),
        source: `app:${row.slug}`,
      });
    }
  }

  return { hosts, unparseable };
}

export function hostsFromProviders(rows: ProviderRow[]): { host: string; source: string }[] {
  const out: { host: string; source: string }[] = [];
  for (const row of rows) {
    // authorizeEndpoint is a browser redirect target, not an egress hop.
    out.push({
      host: hostFromUrl(row.tokenEndpoint),
      source: `provider:${row.ref}`,
    });
    for (const origin of row.apiOrigins) {
      out.push({
        host: hostFromUrl(origin),
        source: `provider:${row.ref}`,
      });
    }
  }
  return out;
}

/** Case-insensitive exact match, or `*.suffix` with at least one label before the suffix. */
export function matchesFqdn(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase();
  if (p.startsWith("*.")) {
    const suffix = p.slice(2);
    if (h === suffix) {
      return false;
    }
    return h.endsWith(`.${suffix}`);
  }
  return h === p;
}

export function aggregateHostNeeds(entries: { host: string; source: string }[]): HostNeed[] {
  const byHost = new Map<string, Set<string>>();
  for (const { host, source } of entries) {
    let sources = byHost.get(host);
    if (!sources) {
      sources = new Set();
      byHost.set(host, sources);
    }
    sources.add(source);
  }
  return [...byHost.entries()]
    .map(([host, sources]) => ({
      host,
      sources: [...sources].sort(),
    }))
    .sort((a, b) => a.host.localeCompare(b.host));
}

export function diffHosts(needed: HostNeed[], deployedPatterns: string[]): HostDiffRow[] {
  return needed.map((row) => ({
    ...row,
    listed: deployedPatterns.some((pattern) => matchesFqdn(row.host, pattern)),
  }));
}

export async function collectNeededHosts(
  prisma: PrismaClient,
): Promise<{ needs: HostNeed[]; unparseable: { slug: string }[] }> {
  const apps = await prisma.app.findMany({
    where: { archivedAt: null },
    select: { slug: true, capabilities: true },
  });
  const providers = await prisma.connectionProvider.findMany({
    where: { env: "prod" },
    select: { ref: true, tokenEndpoint: true, apiOrigins: true },
  });

  const fromApps = hostsFromApps(apps);
  const fromProviders = hostsFromProviders(
    providers.map((p) => ({
      ref: p.ref,
      tokenEndpoint: p.tokenEndpoint,
      apiOrigins: Array.isArray(p.apiOrigins)
        ? p.apiOrigins.filter((x): x is string => typeof x === "string")
        : [],
    })),
  );
  const needs = aggregateHostNeeds([...fromApps.hosts, ...fromProviders]);

  return { needs, unparseable: fromApps.unparseable };
}
