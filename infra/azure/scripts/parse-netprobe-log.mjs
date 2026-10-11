#!/usr/bin/env node
/**
 * Extract egress.netprobe_result JSON from Container Apps job log text (stdin).
 * Prints the summary object as one line, or exits 1 when not found.
 */
import { readFileSync } from "node:fs";

const text = readFileSync(0, "utf8");
for (const line of text.split("\n")) {
  const start = line.indexOf("{");
  if (start < 0) {
    continue;
  }
  try {
    const o = JSON.parse(line.slice(start));
    if (o.event === "egress.netprobe_result") {
      process.stdout.write(`${JSON.stringify(o)}\n`);
      process.exit(0);
    }
  } catch {
    /* not JSON */
  }
}
process.exit(1);
