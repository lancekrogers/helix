import { describe, expect, it } from "vitest";
import * as telemetry from "./telemetry.js";
import {
  ADMISSION_DENIAL_REASONS,
  CUT_CHARGE_BASES,
  FORBIDDEN_URL_ATTRS,
  REGISTRY_LOAD_OUTCOMES,
  SESSION_DENIAL_REASONS,
} from "./telemetry.js";

/**
 * The vocabulary is plain strings, so most of it cannot be got wrong in a way a
 * type catches. What these pin is the two failure modes that are silent: a
 * duplicated key (two dimensions quietly merge into one time series) and a
 * name drifting off the `helix.` prefix an alert rule globs on.
 */

function constantsMatching(prefix: string): [string, string][] {
  const out: [string, string][] = [];
  for (const [name, value] of Object.entries<unknown>(telemetry)) {
    if (name.startsWith(prefix) && typeof value === "string") out.push([name, value]);
  }
  return out;
}

describe("the telemetry vocabulary", () => {
  it("prefixes every instrument name with `helix.`", () => {
    const instruments = constantsMatching("INSTR_");
    expect(instruments.length).toBeGreaterThan(0);
    for (const [name, value] of instruments) {
      expect(value, name).toMatch(/^helix\.[a-z_]+(\.[a-z_]+)*$/);
    }
  });

  it("prefixes every attribute key with `helix.`", () => {
    const attrs = constantsMatching("ATTR_");
    expect(attrs.length).toBeGreaterThan(0);
    for (const [name, value] of attrs) {
      expect(value, name).toMatch(/^helix\.[a-z_]+(\.[a-z_]+)*$/);
    }
  });

  it("has no duplicate instrument or attribute values", () => {
    // A copy-paste that reuses a value doesn't fail to compile and doesn't fail
    // at runtime — the two call sites just write to the same series, and the
    // dashboard shows a plausible-looking sum of unrelated things.
    for (const prefix of ["INSTR_", "ATTR_"]) {
      const values = constantsMatching(prefix).map(([, v]) => v);
      expect(new Set(values).size, `${prefix} values are not unique`).toBe(values.length);
    }
  });

  it("forbids exactly the URL attributes that carry a whole URL", () => {
    // Pinned as a list rather than described, because the ESLint rule and
    // ADR-0037 decision 6 both name these four and all three must agree.
    expect([...FORBIDDEN_URL_ATTRS]).toEqual(["url.full", "http.url", "http.target", "url.query"]);
  });

  it("never forbids the two attributes we are told to record instead", () => {
    expect(FORBIDDEN_URL_ATTRS).not.toContain("url.path");
    expect(FORBIDDEN_URL_ATTRS).not.toContain("http.route");
  });

  it("keeps the bounded dimensions bounded", () => {
    // `userOid` is unbounded and personal; these two are neither, which is why
    // they are allowed to be metric labels at all (ADR-0037 decision 8).
    expect(SESSION_DENIAL_REASONS.length).toBeLessThanOrEqual(8);
    expect(new Set(SESSION_DENIAL_REASONS).size).toBe(SESSION_DENIAL_REASONS.length);
    expect([...REGISTRY_LOAD_OUTCOMES]).toEqual(["failed", "never_loaded"]);
    expect([...CUT_CHARGE_BASES]).toEqual(["measured", "estimated", "mixed"]);
    expect([...ADMISSION_DENIAL_REASONS]).toEqual(["app_budget_day", "app_budget_burst"]);
  });

  it("keeps the consent-start outcome vocabulary bounded and duplicate-free", () => {
    // The edge's start-route span — the operator-visible vocabulary fixes the
    // six values; a seventh would be a vocabulary nobody
    // dashboards.
    expect([...telemetry.CONSENT_START_OUTCOMES]).toEqual([
      "started",
      "signin_required",
      "already_connected",
      "unavailable",
      "forbidden",
      "error",
    ]);
  });

  it("orders the duration buckets ascending and covers past a slow LLM stream", () => {
    const buckets = [...telemetry.DURATION_BUCKETS_MS];
    expect(buckets).toEqual([...buckets].sort((a, b) => a - b));
    expect(new Set(buckets).size).toBe(buckets.length);
    // The whole reason for a custom boundary list: OTel's default tops out at
    // 10s, and an LLM stream routinely runs longer.
    expect(Math.max(...buckets)).toBeGreaterThan(10_000);
  });
});
