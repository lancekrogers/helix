import { describe, expect, it } from "vitest";
import { DenialThrottle } from "./denialThrottle.js";
import { InMemoryCounterStore } from "./counterStore.js";

/**
 * The cap on metered allowlist denials. Without it the `forbidden` write is the
 * one ledger append no gate bounds — see the class docblock.
 */
describe("DenialThrottle", () => {
  const throttle = (max: number, now?: () => number) =>
    new DenialThrottle(new InMemoryCounterStore(now), { max, windowMs: 60_000 });

  it("meters the first `max` denials in a window and drops the rest", async () => {
    const t = throttle(3);
    const decisions = [];
    for (let i = 0; i < 6; i += 1) decisions.push(await t.admit("app-a", "prod"));

    expect(decisions.map((d) => d.meter)).toEqual([true, true, true, false, false, false]);
  });

  it("reports magnitude once, not once per dropped request", async () => {
    const t = throttle(2);
    const logged: number[] = [];
    for (let i = 0; i < 40; i += 1) {
      const d = await t.admit("app-a", "prod");
      if (d.suppressedAt !== undefined) logged.push(d.suppressedAt);
    }
    // 38 suppressed attempts produce exactly one log line — the first.
    expect(logged).toEqual([3]);
  });

  it("budgets each app separately", async () => {
    const t = throttle(1);
    expect((await t.admit("app-a", "prod")).meter).toBe(true);
    expect((await t.admit("app-a", "prod")).meter).toBe(false);
    // A different app is untouched by the noisy one's spend.
    expect((await t.admit("app-b", "prod")).meter).toBe(true);
  });

  it("budgets each env separately", async () => {
    // Everything else in this ledger partitions on env; a dev-token loop must
    // not burn the prod app's denial budget.
    const t = throttle(1);
    expect((await t.admit("app-a", "dev")).meter).toBe(true);
    expect((await t.admit("app-a", "dev")).meter).toBe(false);
    expect((await t.admit("app-a", "prod")).meter).toBe(true);
  });

  it("refills when the window rolls over", async () => {
    let clock = 0;
    const t = throttle(1, () => clock);
    expect((await t.admit("app-a", "prod")).meter).toBe(true);
    expect((await t.admit("app-a", "prod")).meter).toBe(false);
    clock += 60_001;
    expect((await t.admit("app-a", "prod")).meter).toBe(true);
  });

  it("keeps LLM-scoped and unscoped buckets independent for the same app and env", async () => {
    const t = throttle(1);
    expect((await t.admit("app-a", "prod", "llm")).meter).toBe(true);
    expect((await t.admit("app-a", "prod", "llm")).meter).toBe(false);
    expect((await t.admit("app-a", "prod")).meter).toBe(true);
    expect((await t.admit("app-a", "prod")).meter).toBe(false);
  });
});
