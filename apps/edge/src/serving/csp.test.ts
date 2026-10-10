import { describe, expect, it } from "vitest";
import {
  APP_CSP,
  buildAppCsp,
  buildLegacyEnforcedAppCsp,
  buildMeasurementReportOnlyCsp,
} from "./csp.js";

function parse(csp: string): Map<string, string> {
  return new Map(
    csp.split("; ").map((d) => {
      const space = d.indexOf(" ");
      return space === -1 ? [d, ""] : [d.slice(0, space), d.slice(space + 1)];
    }),
  );
}

const directives = parse(APP_CSP);

// The strict directives ARE the containment (architecture §4.4). If one of
// these assertions fails, a diff loosened the data-flow boundary — that is a
// security review, not a test update.
describe("APP_CSP strict data-flow directives", () => {
  it("pins connect-src to 'self' exactly", () => {
    expect(directives.get("connect-src")).toBe("'self'");
  });

  it("pins form-action to 'self' exactly (cross-app CSRF, §4.2)", () => {
    expect(directives.get("form-action")).toBe("'self'");
  });

  it("pins frame-ancestors to 'none' exactly", () => {
    expect(directives.get("frame-ancestors")).toBe("'none'");
  });

  it("pins base-uri to 'self' exactly", () => {
    expect(directives.get("base-uri")).toBe("'self'");
  });

  it("pins img-src to 'self' data: blob: exactly", () => {
    expect(directives.get("img-src")).toBe("'self' data: blob:");
  });

  it("pins object-src to 'none' exactly", () => {
    expect(directives.get("object-src")).toBe("'none'");
  });
});

describe("APP_CSP relaxed code-provenance directives", () => {
  it("permits inline scripts and eval (vibe-coded single-file apps)", () => {
    const script = directives.get("script-src") ?? "";
    expect(script).toContain("'unsafe-inline'");
    expect(script).toContain("'unsafe-eval'");
    expect(script).toContain("'wasm-unsafe-eval'");
  });
});

describe("buildAppCsp — per-app external origins (§6.2)", () => {
  it("widens connect-src and img-src with approved origins", () => {
    const d = parse(buildAppCsp(["https://api.foo.com", "https://b.example.com"]));
    expect(d.get("connect-src")).toBe("'self' https://api.foo.com https://b.example.com");
    expect(d.get("img-src")).toBe("'self' data: blob: https://api.foo.com https://b.example.com");
  });

  it("normalizes a URL with a path down to its origin and dedupes", () => {
    const d = parse(buildAppCsp(["https://api.foo.com/v1", "https://api.foo.com/v2"]));
    expect(d.get("connect-src")).toBe("'self' https://api.foo.com");
  });

  it("drops invalid origins (fail-closed — never widen on garbage)", () => {
    const d = parse(buildAppCsp(["not a url", ""]));
    expect(d.get("connect-src")).toBe("'self'");
  });

  it("includes wss origins in connect-src but not img-src", () => {
    const origins = ["https://api.foo.com", "wss://live.foo.com"];
    const d = parse(buildAppCsp(origins));
    expect(d.get("connect-src")).toBe("'self' https://api.foo.com wss://live.foo.com");
    expect(d.get("img-src")).toBe("'self' data: blob: https://api.foo.com");
  });

  it("drops hostnames with CSP metacharacters", () => {
    const d = parse(buildAppCsp(["https://x;connect-src"]));
    expect(d.get("connect-src")).toBe("'self'");
    expect(d.get("img-src")).toBe("'self' data: blob:");
  });

  it("with no origins equals the strict baseline", () => {
    const d = parse(buildAppCsp());
    expect(d.get("connect-src")).toBe("'self'");
    expect(d.get("img-src")).toBe("'self' data: blob:");
    expect(d.get("object-src")).toBe("'none'");
  });

  it("always points report-uri at the same-origin sink", () => {
    expect(parse(buildAppCsp()).get("report-uri")).toBe("/_csp-report");
    expect(parse(buildAppCsp(["https://api.foo.com"])).get("report-uri")).toBe("/_csp-report");
  });

  it("widens img-src only with imgSrcExtra (not connect-src) and dedupes", () => {
    const d = parse(
      buildAppCsp(["https://api.foo.com"], { imgSrcExtra: ["https://images.example.com"] }),
    );
    expect(d.get("connect-src")).toBe("'self' https://api.foo.com");
    expect(d.get("img-src")).toBe(
      "'self' data: blob: https://api.foo.com https://images.example.com",
    );
    const deduped = parse(
      buildAppCsp(["https://api.foo.com"], { imgSrcExtra: ["https://api.foo.com"] }),
    );
    expect(deduped.get("img-src")).toBe("'self' data: blob: https://api.foo.com");
  });

  it("restores https: in img-src when imgSrcAllowAll is true", () => {
    const d = parse(
      buildAppCsp(["https://api.foo.com", "wss://live.foo.com"], { imgSrcAllowAll: true }),
    );
    expect(d.get("img-src")).toBe("https: data: blob: https://api.foo.com");
    expect(d.get("connect-src")).toContain("wss://live.foo.com");
    expect(d.get("object-src")).toBe("'none'");
  });

  it("never puts https:, http:, or * in default img-src for hostile inputs", () => {
    const d = parse(
      buildAppCsp(["*", "https:", "http://a.example", "https://*.a.example", "not a url", ""]),
    );
    const tokens = (d.get("img-src") ?? "").split(" ");
    expect(tokens).not.toContain("https:");
    expect(tokens).not.toContain("http:");
    expect(tokens.some((t) => t.includes("*"))).toBe(false);
  });

  it("drops a malformed extra origin like external origins", () => {
    const d = parse(buildAppCsp([], { imgSrcExtra: ["not a url"] }));
    expect(d.get("img-src")).toBe("'self' data: blob:");
  });
});

describe("measurement mode (EDGE_IMG_SRC_REPORT_ONLY)", () => {
  it("tightens img-src and adds object-src only on Report-Only", () => {
    const enforced = parse(buildLegacyEnforcedAppCsp());
    const reportOnly = parse(buildMeasurementReportOnlyCsp());
    expect(reportOnly.get("img-src")).toBe("'self' data: blob:");
    expect(reportOnly.get("object-src")).toBe("'none'");
    expect(enforced.get("object-src")).toBeUndefined();
    expect(enforced.get("img-src")).toBe("https: data: blob:");
    for (const [key, value] of enforced) {
      if (key === "img-src" || key === "object-src") continue;
      expect(reportOnly.get(key), key).toBe(value);
    }
  });

  it("puts wss in connect-src only across measurement mode", () => {
    const enforced = parse(
      buildLegacyEnforcedAppCsp(["wss://live.foo.com", "https://api.foo.com"]),
    );
    expect(enforced.get("connect-src")).toContain("wss://live.foo.com");
    expect(enforced.get("img-src")).toBe("https: data: blob: https://api.foo.com");
    const reportOnly = parse(
      buildMeasurementReportOnlyCsp(["wss://live.foo.com", "https://api.foo.com"]),
    );
    expect(reportOnly.get("connect-src")).toContain("wss://live.foo.com");
    expect(reportOnly.get("img-src")).toBe("'self' data: blob: https://api.foo.com");
  });

  it("puts approved origins in img-src and connect-src; imgSrcExtra only in img-src", () => {
    const d = parse(
      buildMeasurementReportOnlyCsp(["https://api.foo.com"], ["https://images.example.com"]),
    );
    expect(d.get("connect-src")).toBe("'self' https://api.foo.com");
    expect(d.get("img-src")).toBe(
      "'self' data: blob: https://api.foo.com https://images.example.com",
    );
    const enforced = parse(buildLegacyEnforcedAppCsp(["https://api.foo.com"]));
    expect(enforced.get("connect-src")).toBe("'self' https://api.foo.com");
    expect(enforced.get("img-src")).toBe("https: data: blob: https://api.foo.com");
    expect(enforced.get("img-src")).not.toContain("images.example.com");
  });

  it("dedupes origins shared between externalOrigins and imgSrcExtra", () => {
    const d = parse(
      buildMeasurementReportOnlyCsp(["https://api.foo.com"], ["https://api.foo.com"]),
    );
    expect(d.get("img-src")).toBe("'self' data: blob: https://api.foo.com");
  });

  it("never puts https:, http:, or * in Report-Only img-src", () => {
    const d = parse(buildMeasurementReportOnlyCsp(["https://api.foo.com"]));
    const tokens = (d.get("img-src") ?? "").split(" ");
    expect(tokens).not.toContain("https:");
    expect(tokens).not.toContain("http:");
    expect(tokens.some((t) => t.includes("*"))).toBe(false);
  });

  it("drops a malformed extra origin like external origins", () => {
    const d = parse(buildMeasurementReportOnlyCsp([], ["not a url"]));
    expect(d.get("img-src")).toBe("'self' data: blob:");
  });
});
