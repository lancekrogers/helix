import { describe, expect, it } from "vitest";
import type { Capabilities } from "./manifest.js";
import {
  ApprovalRequestSchema,
  BASELINE_DOLLARS_PER_DAY,
  BASELINE_WRITES_PER_DAY,
  applyDeltas,
  captureSnapshot,
  classifyChange,
  classifyVisibilityChange,
  fetchOriginKey,
  isProviderBindingEffective,
  maxRisk,
  parseArrayDeltaPath,
  parseFetchOriginKey,
  snapshotConflicts,
  summarizePriorDecisions,
  touchedAreas,
  visibilityLabel,
  type Delta,
  type PriorDecisionRow,
  type Risk,
} from "./approval.js";
import type { VisibilityMode } from "./visibility.js";

const EMPTY: Capabilities = { mcp: [], externalOrigins: [] };

function paths(deltas: { path: string }[]): string[] {
  return deltas.map((d) => d.path);
}

describe("classifyChange — LLM", () => {
  it("baselines a curated model and gates a non-curated one", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      llm: { models: ["claude-fable-5", "gpt-5"], dollarsPerDay: BASELINE_DOLLARS_PER_DAY },
    });
    expect(paths(r.baselineDeltas)).toContain("llm.models[+claude-fable-5]");
    expect(paths(r.elevatedDeltas)).toEqual(["llm.models[+gpt-5]"]);
    expect(r.risk).toBe("med");
  });

  it("gates a spend budget above baseline but not at/under it", () => {
    const under = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: BASELINE_DOLLARS_PER_DAY },
    });
    expect(under.elevatedDeltas).toHaveLength(0);

    const over = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: BASELINE_DOLLARS_PER_DAY + 1 },
    });
    expect(paths(over.elevatedDeltas)).toEqual(["llm.dollarsPerDay"]);
  });

  it("elevates removing an LLM spend cap (requested unset may exceed install default)", () => {
    const eff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: 500 },
    };
    const r = classifyChange(eff, { mcp: [], externalOrigins: [], llm: { models: [] } });
    expect(paths(r.elevatedDeltas)).toEqual(["llm.dollarsPerDay"]);
    expect(r.baselineDeltas).toHaveLength(0);
  });

  it("treats adding a cap (unset default → capped) as baseline privilege reduction", () => {
    const eff: Capabilities = { mcp: [], externalOrigins: [], llm: { models: [] } };
    const r = classifyChange(eff, {
      mcp: [],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: 10 },
    });
    expect(r.elevatedDeltas).toHaveLength(0);
    expect(paths(r.baselineDeltas)).toContain("llm.dollarsPerDay");
  });

  it("lowering a budget that stays above baseline is still baseline (reduction)", () => {
    const eff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: BASELINE_DOLLARS_PER_DAY * 5 },
    };
    const r = classifyChange(eff, {
      mcp: [],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: BASELINE_DOLLARS_PER_DAY * 2 },
    });
    expect(r.elevatedDeltas).toHaveLength(0);
  });

  it("classifies unset LLM budget changes against the install default", () => {
    const to100 = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: 100 },
    });
    expect(paths(to100.elevatedDeltas)).toEqual(["llm.dollarsPerDay"]);

    const to50 = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: BASELINE_DOLLARS_PER_DAY },
    });
    expect(to50.elevatedDeltas).toHaveLength(0);

    const unsetGrant: Capabilities = { mcp: [], externalOrigins: [], llm: { models: [] } };
    const stillUnset = classifyChange(unsetGrant, {
      mcp: [],
      externalOrigins: [],
      llm: { models: [] },
    });
    expect(stillUnset.baselineDeltas).toHaveLength(0);
    expect(stillUnset.elevatedDeltas).toHaveLength(0);
  });

  it("elevates a brand-new LLM grant with no spend cap (unset counts as unlimited)", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      llm: { models: ["claude-opus-4-8"] },
    });
    expect(paths(r.baselineDeltas)).toContain("llm.models[+claude-opus-4-8]");
    expect(paths(r.elevatedDeltas)).toEqual(["llm.dollarsPerDay"]);
  });

  it("baselines a brand-new LLM grant when the cap is at or under the threshold", () => {
    const atBaseline = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      llm: { models: ["claude-opus-4-8"], dollarsPerDay: BASELINE_DOLLARS_PER_DAY },
    });
    expect(atBaseline.elevatedDeltas).toHaveLength(0);
    expect(paths(atBaseline.baselineDeltas)).toContain("llm.dollarsPerDay");

    const under = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: 10 },
    });
    expect(under.elevatedDeltas).toHaveLength(0);
  });

  it("elevates a brand-new LLM grant when the cap is above the threshold", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: BASELINE_DOLLARS_PER_DAY + 1 },
    });
    expect(paths(r.elevatedDeltas)).toEqual(["llm.dollarsPerDay"]);
  });

  it("still treats removing data and fetch caps as elevated (unset remains unlimited)", () => {
    const dataEff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      data: {
        user: true,
        collections: [],
        sharedRead: [],
        sharedWrite: [],
        sharedReadPrefixes: [],
        sharedWritePrefixes: [],
        writesPerDay: 500,
      },
    };
    const dataR = classifyChange(dataEff, {
      mcp: [],
      externalOrigins: [],
      data: {
        user: true,
        collections: [],
        sharedRead: [],
        sharedWrite: [],
        sharedReadPrefixes: [],
        sharedWritePrefixes: [],
      },
    });
    expect(paths(dataR.elevatedDeltas)).toEqual(["data.writesPerDay"]);

    const fetchEff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [], requestsPerDay: 500 },
    };
    const fetchR = classifyChange(fetchEff, {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [] },
    });
    expect(paths(fetchR.elevatedDeltas)).toEqual(["fetch.requestsPerDay"]);
  });
});

describe("classifyChange — mcp / origins / data", () => {
  it("gates any MCP server as high risk", () => {
    const r = classifyChange(EMPTY, { mcp: ["pagerduty"], externalOrigins: [] });
    expect(paths(r.elevatedDeltas)).toEqual(["mcp[+pagerduty]"]);
    expect(r.risk).toBe("high");
  });

  it("emits one delta per requested server — a multi-server ask is a list of rows, not one", () => {
    const r = classifyChange(EMPTY, {
      mcp: ["pagerduty", "datadog", "github"],
      externalOrigins: [],
    });
    expect(paths(r.elevatedDeltas)).toEqual(["mcp[+pagerduty]", "mcp[+datadog]", "mcp[+github]"]);
    for (const d of r.elevatedDeltas) expect(d.risk).toBe("high");
  });

  it("gates any external origin added", () => {
    const r = classifyChange(EMPTY, { mcp: [], externalOrigins: ["https://api.foo.com"] });
    expect(paths(r.elevatedDeltas)).toEqual(["externalOrigins[+https://api.foo.com]"]);
    expect(r.risk).toBe("med");
  });

  it("treats data scopes (user/collections/shared) as baseline", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      data: { user: true, collections: ["contacts"], sharedRead: ["cfg"], sharedWrite: [] },
    });
    expect(r.elevatedDeltas).toHaveLength(0);
    expect(paths(r.baselineDeltas)).toEqual(
      expect.arrayContaining(["data.user", "data.collections[+contacts]", "data.sharedRead[+cfg]"]),
    );
  });

  it("gates a data write budget above baseline", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      data: {
        user: false,
        collections: [],
        sharedRead: [],
        sharedWrite: [],
        writesPerDay: BASELINE_WRITES_PER_DAY + 1,
      },
    });
    expect(paths(r.elevatedDeltas)).toEqual(["data.writesPerDay"]);
  });

  // ADR-0042 decision 4: one prefix element covers unboundedly many keys chosen
  // by the app at runtime, so it must not ride the literal arrays' baseline path
  // OR their delta paths — a reviewer has to see it as its own kind of grant.
  it("gates a shared prefix grant as elevated but low risk, on its own delta path", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      // The schema couples write prefixes to a budget (review finding 3): the
      // bound is a baseline reduction, so it commits immediately — in place
      // BEFORE the elevated grant it bounds can activate.
      data: {
        sharedReadPrefixes: ["record:"],
        sharedWritePrefixes: ["record:"],
        writesPerDay: 10_000,
      },
    });
    expect(paths(r.elevatedDeltas)).toEqual([
      "data.sharedReadPrefixes[+record:]",
      "data.sharedWritePrefixes[+record:]",
    ]);
    expect(paths(r.baselineDeltas)).toContain("data.writesPerDay");
    // Low, not med/high: within the app's visibility gate a prefix is not
    // meaningfully more dangerous than the literal grant it generalizes.
    expect(r.risk).toBe("low");
  });

  it("prefix removal is baseline privilege reduction, and round-trips via applyDeltas", () => {
    const eff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      data: {
        user: false,
        collections: [],
        sharedRead: [],
        sharedWrite: [],
        sharedReadPrefixes: ["record:", "cfg:"],
        sharedWritePrefixes: [],
      },
    };
    const r = classifyChange(eff, {
      mcp: [],
      externalOrigins: [],
      data: { user: false, sharedReadPrefixes: ["record:"] },
    });
    expect(r.elevatedDeltas).toHaveLength(0);
    expect(paths(r.baselineDeltas)).toEqual(["data.sharedReadPrefixes[-cfg:]"]);
    const applied = applyDeltas(eff, r.baselineDeltas);
    expect(applied.data?.sharedReadPrefixes).toEqual(["record:"]);
  });

  it("applyDeltas lands an approved prefix grant from the elevated bundle", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      data: { sharedWritePrefixes: ["record:"], writesPerDay: 10_000 },
    });
    // The approve-time base always carries the budget: it was the baseline half
    // of the same submission, committed at file time (the schema refuses the
    // requested state without it). The elevated bundle carries only the grant.
    const base = applyDeltas(EMPTY, r.baselineDeltas);
    expect(base.data?.writesPerDay).toBe(10_000);
    const applied = applyDeltas(base, r.elevatedDeltas);
    expect(applied.data?.sharedWritePrefixes).toEqual(["record:"]);
    // The literal arrays are untouched by a prefix delta — the two paths cannot
    // bleed into each other at approve time.
    expect(applied.data?.sharedWrite).toEqual([]);
  });

  it("a literal shared grant stays baseline next to an elevated prefix grant", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      data: { sharedRead: ["leaderboard"], sharedReadPrefixes: ["record:"] },
    });
    expect(paths(r.baselineDeltas)).toEqual(["data.sharedRead[+leaderboard]"]);
    expect(paths(r.elevatedDeltas)).toEqual(["data.sharedReadPrefixes[+record:]"]);
  });
});

describe("classifyChange — fetch proxy", () => {
  it("gates a keyless proxied origin as med", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [{ origin: "https://api.github.com" }] },
    });
    expect(paths(r.elevatedDeltas)).toEqual(["fetch.origins[+https://api.github.com]"]);
    expect(r.risk).toBe("med");
  });

  it("gates a secret-bound proxied origin as high", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [{ origin: "https://api.stripe.com", connection: "stripe" }] },
    });
    expect(paths(r.elevatedDeltas)).toEqual([
      "fetch.origins[+https://api.stripe.com→secret:stripe]",
    ]);
    expect(r.risk).toBe("high");
  });

  it("treats the shim toggle as baseline ergonomics", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: true, origins: [] },
    });
    expect(r.elevatedDeltas).toHaveLength(0);
    expect(paths(r.baselineDeltas)).toContain("fetch.shim");
  });

  it("the connect helper is its own baseline delta — a connect-only change persists", () => {
    // The connect sub-option has no legacy alias to ride, so without
    // its own path the classifier produced no delta and the grant silently
    // failed to persist (the reported manifest never changed).
    const requested: Capabilities = {
      mcp: [],
      externalOrigins: [],
      shim: { fetch: false, connect: true },
    };
    const r = classifyChange(EMPTY, requested);
    expect(r.elevatedDeltas).toHaveLength(0);
    expect(paths(r.baselineDeltas)).toEqual(["shim.connect"]);
    const applied = applyDeltas(EMPTY, r.baselineDeltas);
    expect(applied.shim).toEqual({ fetch: false, connect: true });
    // Independent sub-options: toggling both at once emits both paths and
    // applies in either order.
    const both = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      shim: { fetch: true, connect: true },
    });
    expect(paths(both.baselineDeltas).sort()).toEqual(["fetch.shim", "shim.connect"]);
    expect(applyDeltas(EMPTY, both.baselineDeltas).shim).toEqual({ fetch: true, connect: true });
    // Revoking connect while the fetch rewrite stays on keeps the rewrite.
    const revoke = applyDeltas(
      { mcp: [], externalOrigins: [], shim: { fetch: true, connect: true } },
      [{ path: "shim.connect", from: true, to: false }],
    );
    expect(revoke.shim).toEqual({ fetch: true, connect: false });
    expect(revoke.fetch?.shim).toBe(true);
  });

  it("gates a fetch request budget above baseline only", () => {
    const under = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [], requestsPerDay: 10_000 },
    });
    expect(under.elevatedDeltas).toHaveLength(0);
    const over = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [], requestsPerDay: 10_001 },
    });
    expect(paths(over.elevatedDeltas)).toEqual(["fetch.requestsPerDay"]);
  });

  it("removing a proxied origin is baseline, and round-trips through applyDeltas", () => {
    const eff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [{ origin: "https://api.github.com", connection: "gh" }] },
    };
    const r = classifyChange(eff, {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [] },
    });
    expect(r.elevatedDeltas).toHaveLength(0);
    expect(paths(r.baselineDeltas)).toEqual(["fetch.origins[-https://api.github.com→secret:gh]"]);
    const applied = applyDeltas(eff, r.baselineDeltas);
    expect(applied.fetch?.origins).toEqual([]);
  });

  it("applyDeltas adds a secret-bound origin from the elevated bundle", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [{ origin: "https://api.stripe.com", connection: "stripe" }] },
    });
    const applied = applyDeltas(EMPTY, r.elevatedDeltas);
    expect(applied.fetch?.origins).toEqual([
      { origin: "https://api.stripe.com", connection: "stripe" },
    ]);
  });
});

// A provider-bound origin classifies like a secret-bound one (high), on the
// extended canonical key form `origin→provider:ref`. Keyless/secret-bound
// classifications are unchanged above.
describe("classifyChange — provider-bound origins", () => {
  it("gates a provider-bound origin add as high, on the provider key form", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      fetch: {
        shim: false,
        origins: [{ origin: "https://api.asana.com", provider: "asana", required: true }],
      },
    });
    expect(paths(r.elevatedDeltas)).toEqual([
      "fetch.origins[+https://api.asana.com→provider:asana]",
    ]);
    expect(r.risk).toBe("high");
  });

  it("round-trips a provider-bound origin through applyDeltas", () => {
    const requested: Capabilities = {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [{ origin: "https://api.asana.com", provider: "asana" }] },
    };
    const r = classifyChange(EMPTY, requested);
    expect(applyDeltas(EMPTY, r.elevatedDeltas).fetch?.origins).toEqual([
      { origin: "https://api.asana.com", provider: "asana" },
    ]);
  });

  it("treats a change of bound provider as remove (baseline) + add (elevated high)", () => {
    const eff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [{ origin: "https://api.asana.com", provider: "asana" }] },
    };
    const r = classifyChange(eff, {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [{ origin: "https://api.asana.com", provider: "github" }] },
    });
    expect(paths(r.baselineDeltas)).toEqual([
      "fetch.origins[-https://api.asana.com→provider:asana]",
    ]);
    expect(paths(r.elevatedDeltas)).toEqual([
      "fetch.origins[+https://api.asana.com→provider:github]",
    ]);
    expect(r.risk).toBe("high");
  });

  it("treats removing a provider binding as baseline, and the removal round-trips", () => {
    const eff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [{ origin: "https://api.asana.com", provider: "asana" }] },
    };
    const r = classifyChange(eff, {
      mcp: [],
      externalOrigins: [],
      fetch: { shim: false, origins: [] },
    });
    expect(r.elevatedDeltas).toHaveLength(0);
    expect(paths(r.baselineDeltas)).toEqual([
      "fetch.origins[-https://api.asana.com→provider:asana]",
    ]);
    expect(applyDeltas(eff, r.baselineDeltas).fetch?.origins).toEqual([]);
  });

  it("keys the three credential kinds apart — the canonical key is the parse's inverse", () => {
    const keyless = { origin: "https://a.example" };
    const secret = { origin: "https://b.example", connection: "s1" };
    const provider = { origin: "https://c.example", provider: "p1" };
    expect(fetchOriginKey(keyless)).toBe("https://a.example");
    expect(fetchOriginKey(secret)).toBe("https://b.example→secret:s1");
    expect(fetchOriginKey(provider)).toBe("https://c.example→provider:p1");
    expect(parseFetchOriginKey(fetchOriginKey(keyless))).toEqual(keyless);
    expect(parseFetchOriginKey(fetchOriginKey(secret))).toEqual(secret);
    expect(parseFetchOriginKey(fetchOriginKey(provider))).toEqual(provider);
  });

  it("classifies a mixed submission by its worst elevated delta", () => {
    const r = classifyChange(EMPTY, {
      mcp: [],
      externalOrigins: [],
      fetch: {
        shim: false,
        origins: [
          { origin: "https://a.example" }, // med, elevated
          { origin: "https://b.example", connection: "s" }, // high
          { origin: "https://c.example", provider: "p" }, // high
        ],
      },
    });
    expect(r.risk).toBe("high");
    expect(r.elevatedDeltas).toHaveLength(3);
  });
});

describe("isProviderBindingEffective — the one binding-effectiveness rule", () => {
  const stamp = {
    ref: "asana",
    env: "prod" as const,
    providerId: "0d7e2c2e-6a1c-4f5e-9a2b-3c4d5e6f7a8b",
    revision: 3,
  };

  it("is effective when id, ref and revision all match the current row", () => {
    expect(
      isProviderBindingEffective(stamp, { id: stamp.providerId, ref: "asana", revision: 3 }),
    ).toBe(true);
  });

  it("is not effective once a sensitive edit advanced the revision", () => {
    expect(
      isProviderBindingEffective(stamp, { id: stamp.providerId, ref: "asana", revision: 4 }),
    ).toBe(false);
  });

  it("is not effective when the provider row is gone (deleted)", () => {
    expect(isProviderBindingEffective(stamp, null)).toBe(false);
    expect(isProviderBindingEffective(stamp, undefined)).toBe(false);
  });

  it("is not effective against a recreated row under the same ref (new surrogate id)", () => {
    expect(
      isProviderBindingEffective(stamp, {
        id: "11111111-1111-4111-8111-111111111111",
        ref: "asana",
        revision: 3,
      }),
    ).toBe(false);
  });

  it("is not effective when the ref moved to a different row", () => {
    expect(
      isProviderBindingEffective(stamp, { id: stamp.providerId, ref: "other", revision: 3 }),
    ).toBe(false);
  });
});

describe("classifyChange — offline (ADR-0035)", () => {
  const withScope = (scope: string): Capabilities => ({
    mcp: [],
    externalOrigins: [],
    offline: { scope },
  });

  it("gates taking the grant as med", () => {
    const r = classifyChange(EMPTY, withScope("/app/"));
    expect(paths(r.elevatedDeltas)).toEqual(["offline.scope"]);
    expect(r.risk).toBe("med");
    expect(applyDeltas(EMPTY, r.elevatedDeltas).offline).toEqual({ scope: "/app/" });
  });

  it("gates moving the scope — a rescope is not a reduction", () => {
    const r = classifyChange(withScope("/app/"), withScope("/shell/"));
    expect(paths(r.elevatedDeltas)).toEqual(["offline.scope"]);
    expect(r.elevatedDeltas[0]).toMatchObject({ from: "/app/", to: "/shell/" });
  });

  it("giving up the grant is baseline, and applyDeltas drops the block", () => {
    const eff = withScope("/app/");
    const r = classifyChange(eff, EMPTY);
    expect(r.elevatedDeltas).toHaveLength(0);
    expect(paths(r.baselineDeltas)).toEqual(["offline.scope"]);
    expect(applyDeltas(eff, r.baselineDeltas).offline).toBeUndefined();
  });

  it("an unchanged scope produces no delta", () => {
    const r = classifyChange(withScope("/app/"), withScope("/app/"));
    expect(r.baselineDeltas).toHaveLength(0);
    expect(r.elevatedDeltas).toHaveLength(0);
  });

  it("is its own conflict area, so a concurrent LLM edit does not stale it", () => {
    const eff = withScope("/app/");
    const snap = captureSnapshot(eff, vis("internal"), touchedAreas([{ path: "offline.scope" }]));
    expect(Object.keys(snap)).toEqual(["offline"]);
    expect(
      snapshotConflicts(snap, { ...eff, llm: { models: ["claude-fable-5"] } }, vis("internal")),
    ).toBe(false);
    expect(snapshotConflicts(snap, withScope("/other/"), vis("internal"))).toBe(true);
  });
});

describe("classifyChange — reductions are always baseline", () => {
  it("removing grants never elevates", () => {
    const eff: Capabilities = {
      mcp: ["pagerduty"],
      externalOrigins: ["https://api.foo.com"],
      llm: { models: ["gpt-5"] },
    };
    const r = classifyChange(eff, EMPTY);
    expect(r.elevatedDeltas).toHaveLength(0);
    expect(paths(r.baselineDeltas)).toEqual(
      expect.arrayContaining([
        "mcp[-pagerduty]",
        "externalOrigins[-https://api.foo.com]",
        "llm.models[-gpt-5]",
      ]),
    );
  });
});

describe("classifyChange — mixed submission splits and risk = max", () => {
  it("commits baseline, bundles elevated, reports max risk", () => {
    const r = classifyChange(EMPTY, {
      mcp: ["pagerduty"], // high, elevated
      externalOrigins: ["https://api.foo.com"], // med, elevated
      llm: { models: ["claude-fable-5"], dollarsPerDay: BASELINE_DOLLARS_PER_DAY }, // baseline
      data: { user: true, collections: [], sharedRead: [], sharedWrite: [] }, // baseline
    });
    expect(r.baselineDeltas.length).toBeGreaterThan(0);
    expect(r.elevatedDeltas.length).toBe(2);
    expect(r.risk).toBe("high");
  });
});

describe("parseArrayDeltaPath — the read side of the classifier's array paths", () => {
  it("splits every field/op/item the classifier writes", () => {
    expect(parseArrayDeltaPath("mcp[+pagerduty]")).toEqual({
      field: "mcp",
      op: "+",
      item: "pagerduty",
    });
    expect(parseArrayDeltaPath("data.sharedWritePrefixes[-record:]")).toEqual({
      field: "data.sharedWritePrefixes",
      op: "-",
      item: "record:",
    });
  });

  it("keeps an item containing brackets whole — the anchored-field-names trap", () => {
    // A greedy `(.*)\[([+-])(.*)\]` would split at the item's inner bracket.
    expect(parseArrayDeltaPath("data.sharedReadPrefixes[-cfg[-v2]]")).toEqual({
      field: "data.sharedReadPrefixes",
      op: "-",
      item: "cfg[-v2]",
    });
  });

  it("returns null for scalar and visibility paths", () => {
    expect(parseArrayDeltaPath("llm.dollarsPerDay")).toBeNull();
    expect(parseArrayDeltaPath("visibility")).toBeNull();
  });
});

describe("per-delta risk travels on the delta", () => {
  /**
   * The queue card renders each delta with its own severity chip, so every
   * delta the classifier emits must carry `risk` — and the request-level
   * aggregate must stay the max across the elevated ones (the UI's fallback
   * for legacy rows depends on that invariant).
   */
  const cases: Array<[string, unknown, Risk]> = [
    ["uncurated llm model", { mcp: [], externalOrigins: [], llm: { models: ["gpt-5"] } }, "med"],
    [
      "spend budget above baseline",
      { mcp: [], externalOrigins: [], llm: { models: [], dollarsPerDay: 500 } },
      "med",
    ],
    ["mcp grant", { mcp: ["pagerduty"], externalOrigins: [] }, "high"],
    ["external origin", { mcp: [], externalOrigins: ["https://api.foo.com"] }, "med"],
    [
      "keyless fetch origin",
      {
        mcp: [],
        externalOrigins: [],
        fetch: { shim: false, origins: [{ origin: "https://api.github.com" }] },
      },
      "med",
    ],
    [
      "secret-bound fetch origin",
      {
        mcp: [],
        externalOrigins: [],
        fetch: { shim: false, origins: [{ origin: "https://api.github.com", connection: "gh" }] },
      },
      "high",
    ],
    [
      "shared read prefix",
      {
        mcp: [],
        externalOrigins: [],
        data: {
          user: false,
          collections: [],
          sharedRead: [],
          sharedWrite: [],
          sharedReadPrefixes: ["cfg:"],
        },
      },
      "low",
    ],
    ["offline scope grant", { mcp: [], externalOrigins: [], offline: { scope: "/app/" } }, "med"],
  ];

  it.each(cases)(
    "%s → every elevated delta carries its classified risk",
    (_name, requested, risk) => {
      const r = classifyChange(EMPTY, requested as Capabilities);
      expect(r.elevatedDeltas.length).toBeGreaterThan(0);
      for (const d of r.elevatedDeltas) expect(d.risk).toBe(risk);
      expect(r.risk).toBe(maxRisk(r.elevatedDeltas.map((d) => d.risk ?? "low")));
    },
  );

  it("visibility delta carries its risk like any other", () => {
    expect(classifyVisibilityChange(vis("internal"), vis("public"))?.delta.risk).toBe("high");
    expect(classifyVisibilityChange(vis("public"), vis("internal"))?.delta.risk).toBe("low");
  });

  it("validates old payloads whose deltas predate the field", () => {
    const legacy = {
      ...ApprovalRequestSchema.parse({
        id: "a1",
        appId: "app1",
        status: "pending",
        risk: "med",
        deltas: [{ path: "externalOrigins[+https://api.foo.com]", to: "https://api.foo.com" }],
        baseSnapshot: {},
        requestedBy: "bob@azx.dev",
        createdAt: new Date().toISOString(),
      }),
    };
    expect(legacy.deltas[0]!.risk).toBeUndefined();
  });
});

/** A `VisibilityState` from the shorthand the tests actually care about. */
const vis = (mode: VisibilityMode, ...groupIds: string[]) => ({ mode, groupIds });

describe("classifyVisibilityChange", () => {
  it("gates → public as high, everything else baseline", () => {
    expect(classifyVisibilityChange(vis("group", "g1"), vis("public"))).toMatchObject({
      elevated: true,
      risk: "high",
    });
    expect(classifyVisibilityChange(vis("public"), vis("internal"))).toMatchObject({
      elevated: false,
    });
    expect(classifyVisibilityChange(vis("internal"), vis("internal"))).toBeNull();
  });

  // The regression this exists for: while this took two bare modes, a
  // group-set edit compared equal and returned null, and `routes/apps.ts` reads
  // null as "no-op" — so changing which group could open an app answered 200,
  // wrote nothing, and audited nothing (ADR-0040 §5).
  it("sees a group-set edit that leaves the mode alone", () => {
    const change = classifyVisibilityChange(vis("group", "eng"), vis("group", "product"));
    expect(change).not.toBeNull();
    expect(change).toMatchObject({ elevated: false, risk: "low" });
    expect(change?.delta).toEqual({
      path: "visibility",
      from: "group:eng",
      to: "group:product",
      risk: "low",
    });
  });

  it("treats adding and removing a group as baseline — the population moves inside the tenant", () => {
    expect(
      classifyVisibilityChange(vis("group", "eng"), vis("group", "eng", "product")),
    ).toMatchObject({ elevated: false, risk: "low" });
    expect(
      classifyVisibilityChange(vis("group", "eng", "product"), vis("group", "eng")),
    ).toMatchObject({ elevated: false, risk: "low" });
  });

  // Order is meaningless in an any-of set, so re-selecting the same groups in a
  // different order must not manufacture a delta — that would write, bump
  // policyVersion, force a projection reload and file an audit row for nothing.
  it("ignores reordering, and normalises the label", () => {
    expect(
      classifyVisibilityChange(vis("group", "eng", "product"), vis("group", "product", "eng")),
    ).toBeNull();
    expect(visibilityLabel(vis("group", "product", "eng"))).toBe("group:eng,product");
    expect(visibilityLabel(vis("internal"))).toBe("internal");
    expect(visibilityLabel(vis("group"))).toBe("group:");
  });

  /**
   * The label was being used as an equality key, and it joins on `,` — so an id
   * that CONTAINS a comma collided with the pair it joins to. Both directions were
   * stuck: the route reads `null` as a no-op, so it answered 200 with no write and
   * no audit row, and an app wrongly scoped to the single id `"eng,prod"` (which
   * admits nobody) could not be corrected to `["eng","prod"]`.
   *
   * The fix compares sets, so the collision is gone regardless of what characters
   * an id contains. The write path additionally refuses the delimiter, but that is
   * hygiene layered on top rather than the thing correctness rests on — which is
   * why this test exercises the classifier directly, with ids the schema would now
   * reject.
   */
  it("does not confuse a comma-containing id with the pair its label joins", () => {
    const pair = vis("group", "eng", "prod");
    const single = vis("group", "eng,prod");
    // The labels genuinely collide — that is the trap, and it is still true.
    expect(visibilityLabel(pair)).toBe(visibilityLabel(single));
    // The classification does not.
    expect(classifyVisibilityChange(pair, single)).not.toBeNull();
    expect(classifyVisibilityChange(single, pair)).not.toBeNull();
  });

  it("treats a duplicated id as no change", () => {
    // `["a","a"]` and `["a"]` are the same set, so re-saving one as the other is
    // not an edit. (The write path dedupes, so this is the read-back case.)
    expect(classifyVisibilityChange(vis("group", "a", "a"), vis("group", "a"))).toBeNull();
  });

  it("still gates a group app going public, group set or not", () => {
    expect(classifyVisibilityChange(vis("group", "eng", "product"), vis("public"))).toMatchObject({
      elevated: true,
      risk: "high",
    });
  });
});

describe("applyDeltas", () => {
  it("round-trips elevated deltas onto effective state", () => {
    const r = classifyChange(EMPTY, {
      mcp: ["pagerduty"],
      externalOrigins: ["https://api.foo.com"],
      llm: { models: ["gpt-5"] },
    });
    const applied = applyDeltas(EMPTY, r.elevatedDeltas);
    expect(applied.mcp).toEqual(["pagerduty"]);
    expect(applied.externalOrigins).toEqual(["https://api.foo.com"]);
    expect(applied.llm?.models).toEqual(["gpt-5"]);
  });

  it("applying only baseline deltas excludes the elevated bundle", () => {
    const requested = {
      mcp: ["pagerduty"],
      externalOrigins: [],
      llm: { models: ["claude-fable-5"] },
    };
    const r = classifyChange(EMPTY, requested);
    const applied = applyDeltas(EMPTY, r.baselineDeltas);
    expect(applied.llm?.models).toEqual(["claude-fable-5"]);
    expect(applied.mcp).toEqual([]); // pagerduty stays out until approved
  });

  it("applies scalar removal (LLM cap removed to install default) from elevated bundle", () => {
    const eff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: 500 },
    };
    const r = classifyChange(eff, { mcp: [], externalOrigins: [], llm: { models: [] } });
    const applied = applyDeltas(eff, r.elevatedDeltas);
    expect(applied.llm?.dollarsPerDay).toBeUndefined();
  });

  // Review finding 5: `[` and `]` are legal in keys and prefixes, and the old
  // greedy ARRAY_PATH bound its field group at the LAST `[+`/`[-` — so the
  // REMOVAL delta for an item containing `[-` split as
  // field "data.sharedReadPrefixes[-cfg", item "v2]" and applyArray's silent
  // fall-through no-op'd it: the owner revoked the grant and got a 200 with the
  // grant intact. The anchored field set makes the split unambiguous.
  it("round-trips an item containing `[-` — the revoked grant actually goes", () => {
    const eff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      data: {
        user: false,
        collections: [],
        sharedRead: [],
        sharedWrite: [],
        sharedReadPrefixes: ["cfg[-v2]", "plain:"],
        sharedWritePrefixes: [],
        writesPerDay: 10,
      },
    };
    const r = classifyChange(eff, {
      mcp: [],
      externalOrigins: [],
      data: { ...eff.data, sharedReadPrefixes: ["plain:"] },
    });
    expect(paths(r.baselineDeltas)).toEqual(["data.sharedReadPrefixes[-cfg[-v2]]"]);
    const applied = applyDeltas(eff, r.baselineDeltas);
    expect(applied.data?.sharedReadPrefixes).toEqual(["plain:"]);
    // And the ADD direction lands too — both directions survive the bracket.
    // (Adds are elevated — every prefix grant is; removals are the baseline
    // privilege reductions asserted above.)
    const add = classifyChange(applied, {
      mcp: [],
      externalOrigins: [],
      data: { ...applied.data, sharedReadPrefixes: ["plain:", "cfg[-v2]"] },
    });
    expect(paths(add.elevatedDeltas)).toEqual(["data.sharedReadPrefixes[+cfg[-v2]]"]);
    expect(applyDeltas(applied, add.elevatedDeltas).data?.sharedReadPrefixes).toEqual([
      "plain:",
      "cfg[-v2]",
    ]);
  });
});

describe("snapshot + conflict (optimistic concurrency)", () => {
  it("captures touched areas and detects a moved value", () => {
    const eff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: 500 },
    };
    const r = classifyChange(eff, {
      mcp: ["pagerduty"],
      externalOrigins: [],
      llm: { models: [], dollarsPerDay: 500 },
    });
    const areas = touchedAreas(r.elevatedDeltas);
    expect(areas).toEqual(["mcp"]);
    const snap = captureSnapshot(eff, vis("internal"), areas);

    // unchanged → no conflict
    expect(snapshotConflicts(snap, eff, vis("internal"))).toBe(false);

    // someone else added an mcp server → conflict
    const moved: Capabilities = { ...eff, mcp: ["other"] };
    expect(snapshotConflicts(snap, moved, vis("internal"))).toBe(true);
  });

  it("detects a visibility move", () => {
    const snap = captureSnapshot(EMPTY, vis("group", "g1"), ["visibility"]);
    expect(snapshotConflicts(snap, EMPTY, vis("group", "g1"))).toBe(false);
    expect(snapshotConflicts(snap, EMPTY, vis("internal"))).toBe(true);
  });

  // A pending → public request filed while the app was scoped to `eng` must not
  // commit blind if someone re-scoped it to `product` in the meantime: the
  // reviewer approved a specific before-state. A mode-only snapshot said "still
  // group" and let it through.
  it("detects a group-set move under an open request", () => {
    const snap = captureSnapshot(EMPTY, vis("group", "eng"), ["visibility"]);
    expect(snapshotConflicts(snap, EMPTY, vis("group", "product"))).toBe(true);
    expect(snapshotConflicts(snap, EMPTY, vis("group", "eng", "product"))).toBe(true);
    expect(snapshotConflicts(snap, EMPTY, vis("group", "eng"))).toBe(false);
  });

  // The live failure the ADR-0042 prefix grants surfaced (2026-09-03): the
  // first data-area elevated request anyone approved auto-bounced with "the
  // effective state changed" when nothing had. The stored `baseSnapshot` is a
  // jsonb column, which re-orders object keys canonically at rest
  // (`user, sharedRead, collections, …`), while the approve-time re-derivation
  // goes through zod, which emits keys in shape order
  // (`user, collections, sharedRead, …`) — and the comparison was
  // `JSON.stringify`, which is key-order sensitive. Other areas' shape and
  // jsonb orders coincide, which is why only the data area bounced.
  it("does not see a jsonb-vs-schema key-order difference as a moved value", () => {
    // The live shape: an app whose baseline part (a literal sharedRead grant)
    // already committed, filing a prefix grant as the elevated bundle.
    const eff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      data: {
        user: false,
        collections: [],
        sharedRead: ["leaderboard"],
        sharedWrite: [],
        sharedReadPrefixes: [],
        sharedWritePrefixes: [],
      },
    };
    const requested = {
      mcp: [],
      externalOrigins: [],
      // A complete draft, as the SPA always sends — the existing literals stay.
      data: { ...eff.data, sharedReadPrefixes: ["record:"] },
    };
    const r = classifyChange(eff, requested);
    expect(paths(r.elevatedDeltas)).toEqual(["data.sharedReadPrefixes[+record:]"]);
    const applied = applyDeltas(eff, r.baselineDeltas);
    expect(applied.data?.sharedRead).toEqual(["leaderboard"]);

    // jsonb's canonical key order for the data area, as Postgres returns the
    // stored snapshot: user(4) < sharedRead(10) < collections(11) = sharedWrite
    // < the prefix arrays — NOT the schema's declaration order.
    const jsonbOrdered = {
      data: {
        user: false,
        sharedRead: ["leaderboard"],
        collections: [],
        sharedWrite: [],
        sharedReadPrefixes: [],
        sharedWritePrefixes: [],
      },
    };
    // The bug this fix exists for, stated directly: the same value in the two
    // orders must not conflict.
    expect(snapshotConflicts(jsonbOrdered, applied, vis("public"))).toBe(false);

    // A REAL move under the request still bounces (that is the feature).
    expect(
      snapshotConflicts(
        jsonbOrdered,
        { ...applied, data: { ...applied.data!, sharedWrite: ["poll"] } },
        vis("public"),
      ),
    ).toBe(true);
    // A grant added inside an area still counts — content, not just order.
    expect(
      snapshotConflicts(
        jsonbOrdered,
        { ...applied, data: { ...applied.data!, sharedRead: ["leaderboard", "extra"] } },
        vis("public"),
      ),
    ).toBe(true);
  });

  // Review finding 2: the stored snapshot is jsonb written when the request was
  // FILED — possibly by a pre-0042 build, before `sharedReadPrefixes` existed —
  // while the approve-time re-derivation parses through the schema, which now
  // defaults those arrays. A defaulted-but-unchanged field is a key-SET
  // difference, not a moved value, and requests never expire (ADR-0039), so a
  // real queue is expected to hold snapshots across deploys. The stored side is
  // normalized through the same schema before comparing — which also guards the
  // NEXT field anyone adds to DataCapabilitySchema.
  it("does not see a schema-defaulted field the stored snapshot predates as a moved value", () => {
    // A snapshot exactly as a pre-0042 build wrote it: no prefix keys at all.
    const preAdr42 = {
      data: { user: true, collections: ["contacts"], sharedRead: [], sharedWrite: [] },
    };
    const eff: Capabilities = {
      mcp: [],
      externalOrigins: [],
      data: {
        user: true,
        collections: ["contacts"],
        sharedRead: [],
        sharedWrite: [],
        sharedReadPrefixes: [],
        sharedWritePrefixes: [],
      },
    };
    expect(snapshotConflicts(preAdr42, eff, vis("internal"))).toBe(false);
    // And a genuinely moved value still conflicts through the normalization.
    expect(
      snapshotConflicts(preAdr42, { ...eff, data: { ...eff.data!, user: false } }, vis("internal")),
    ).toBe(true);
  });
});

describe("maxRisk", () => {
  it("orders low < med < high", () => {
    expect(maxRisk([])).toBe("low");
    expect(maxRisk(["low", "med"])).toBe("med");
    expect(maxRisk(["med", "high", "low"])).toBe("high");
  });
});

describe("summarizePriorDecisions (issue #26)", () => {
  const current: Delta[] = [{ path: "mcp[+pagerduty]", to: "pagerduty" }];
  const decided = (over: Partial<PriorDecisionRow>): PriorDecisionRow => ({
    status: "denied",
    deltas: [{ path: "mcp[+pagerduty]", to: "pagerduty" }],
    decisionNote: "no",
    decidedBy: "alice@azx.io",
    decidedAt: "2026-08-13T00:00:00.000Z",
    ...over,
  });

  it("returns undefined when there are no prior decisions (first-time request)", () => {
    expect(summarizePriorDecisions(current, [])).toBeUndefined();
  });

  it("flags an exact-grant denial loudly (deniedSameGrant, ⊆ deniedSameArea)", () => {
    const prior = [decided({}), decided({}), decided({})];
    const s = summarizePriorDecisions(current, prior);
    expect(s).toMatchObject({ total: 3, deniedSameGrant: 3, deniedSameArea: 3 });
    expect(s?.last).toEqual({
      status: "denied",
      note: "no",
      decidedBy: "alice@azx.io",
      decidedAt: "2026-08-13T00:00:00.000Z",
    });
  });

  it("flags a same-area (not same-grant) denial quietly", () => {
    // A different MCP server was denied before — same area, not the same grant.
    const prior = [decided({ deltas: [{ path: "mcp[+other]", to: "other" }] })];
    const s = summarizePriorDecisions(current, prior);
    expect(s).toMatchObject({ total: 1, deniedSameGrant: 0, deniedSameArea: 1 });
  });

  it("does not raise either flag for a denial in an unrelated area", () => {
    const prior = [decided({ deltas: [{ path: "llm.dollarsPerDay", from: 50, to: 500 }] })];
    const s = summarizePriorDecisions(current, prior);
    expect(s).toMatchObject({ total: 1, deniedSameGrant: 0, deniedSameArea: 0 });
  });

  it("counts non-denied decisions as history but never raises the flag", () => {
    const prior: PriorDecisionRow[] = [
      decided({ status: "approved", decisionNote: null, decidedAt: "2026-08-14T00:00:00.000Z" }),
      decided({ status: "withdrawn", decisionNote: null }),
      decided({ status: "needs_changes", decisionNote: "tighten scope" }),
    ];
    const s = summarizePriorDecisions(current, prior);
    // total counts all; the denied-flags stay at zero; last is the newest (head).
    expect(s).toMatchObject({ total: 3, deniedSameGrant: 0, deniedSameArea: 0 });
    expect(s?.last?.status).toBe("approved");
  });

  it("takes `last` from the head (caller orders newest-decision-first)", () => {
    const prior: PriorDecisionRow[] = [
      decided({ decidedAt: "2026-08-14T00:00:00.000Z", decisionNote: "newest" }),
      decided({ decidedAt: "2026-08-10T00:00:00.000Z", decisionNote: "older" }),
    ];
    expect(summarizePriorDecisions(current, prior)?.last?.note).toBe("newest");
  });
});
