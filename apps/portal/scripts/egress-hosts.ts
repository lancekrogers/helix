import { readFileSync } from "node:fs";
import { createPrismaClient } from "../src/db/client.js";
import { collectNeededHosts, diffHosts, type HostDiffRow } from "../src/netControls/egressHosts.js";

interface Options {
  deployed: string[];
  json: boolean;
  check: boolean;
}

function parseArgs(argv: string[]): Options {
  const deployed: string[] = [];
  let json = false;
  let check = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--") {
      continue;
    }
    if (arg === "--json") {
      json = true;
    } else if (arg === "--check") {
      check = true;
    } else if (arg === "--deployed") {
      const raw = argv[++i];
      if (raw === undefined) {
        throw new Error("--deployed requires a comma-separated host list");
      }
      deployed.push(
        ...raw
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      );
    } else if (arg === "--deployed-file") {
      const path = argv[++i];
      if (path === undefined) {
        throw new Error("--deployed-file requires a path or - for stdin");
      }
      const text = path === "-" ? readStdinSync() : readFileSync(path, "utf8");
      const parsed = JSON.parse(text) as unknown;
      if (!Array.isArray(parsed) || !parsed.every((x) => typeof x === "string")) {
        throw new Error("--deployed-file must be a JSON array of strings");
      }
      deployed.push(...parsed);
    } else if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  return { deployed, json, check };
}

function readStdinSync(): string {
  return readFileSync(0, "utf8");
}

function printUsage(): void {
  console.error(`Usage:
  pnpm --filter @azx-pbc/portal egress:hosts -- [--deployed a.example.com,b.example.com]
       [--deployed-file path.json | -] [--json] [--check]

Compares hosts required by approved apps and prod connection providers against a
deployed firewall allow-list (exact hosts or *.suffix patterns).`);
}

function printTable(rows: HostDiffRow[], unparseable: { slug: string }[]): void {
  for (const { slug } of unparseable) {
    console.log(`${slug}\tUNPARSEABLE\t(skipped)`);
  }
  for (const row of rows) {
    const status = row.listed ? "listed" : "MISSING";
    console.log(`${row.host}\t${row.sources.join(", ")}\t${status}`);
  }
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const prisma = createPrismaClient();
  try {
    const { needs, unparseable } = await collectNeededHosts(prisma);
    const rows = diffHosts(needs, opts.deployed);

    if (opts.json) {
      console.log(JSON.stringify({ hosts: rows, unparseable }, null, 2));
    } else {
      printTable(rows, unparseable);
    }

    if (opts.check && rows.some((r) => !r.listed)) {
      process.exitCode = 1;
    }
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
