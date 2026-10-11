import { describe, expect, it } from "vitest";
import {
  aggregateHostNeeds,
  diffHosts,
  hostFromUrl,
  hostsFromApps,
  hostsFromProviders,
  matchesFqdn,
} from "./egressHosts.js";

describe("hostFromUrl", () => {
  it("drops scheme, path, port, and lowercases", () => {
    expect(hostFromUrl("https://API.Example.COM:8443/v1/x")).toBe("api.example.com");
  });
});

describe("hostsFromApps", () => {
  it("collects fetch origins per app", () => {
    const { hosts, unparseable } = hostsFromApps([
      {
        slug: "a",
        capabilities: { fetch: { origins: [{ origin: "https://one.example.com" }] } },
      },
      {
        slug: "b",
        capabilities: { fetch: { origins: [{ origin: "https://one.example.com" }] } },
      },
    ]);
    expect(unparseable).toEqual([]);
    const merged = aggregateHostNeeds(hosts);
    expect(merged).toEqual([{ host: "one.example.com", sources: ["app:a", "app:b"] }]);
  });

  it("reports unparseable manifests without throwing", () => {
    const { hosts, unparseable } = hostsFromApps([
      { slug: "bad", capabilities: { fetch: { origins: [{ origin: "not-a-url" }] } } },
    ]);
    expect(hosts).toEqual([]);
    expect(unparseable).toEqual([{ slug: "bad" }]);
  });
});

describe("hostsFromProviders", () => {
  it("includes token endpoint and api origins, not authorize", () => {
    const hosts = hostsFromProviders([
      {
        ref: "vendor",
        tokenEndpoint: "https://token.vendor.example/oauth/token",
        apiOrigins: ["https://api.vendor.example"],
      },
    ]);
    expect(hosts.map((h) => h.host).sort()).toEqual(["api.vendor.example", "token.vendor.example"]);
    expect(hosts.every((h) => h.source === "provider:vendor")).toBe(true);
  });
});

describe("matchesFqdn", () => {
  it("matches wildcard suffix patterns", () => {
    expect(matchesFqdn("a.example.com", "*.example.com")).toBe(true);
    expect(matchesFqdn("a.b.example.com", "*.example.com")).toBe(true);
    expect(matchesFqdn("example.com", "*.example.com")).toBe(false);
    expect(matchesFqdn("badexample.com", "*.example.com")).toBe(false);
  });

  it("matches exact hosts case-insensitively", () => {
    expect(matchesFqdn("API.Example.COM", "api.example.com")).toBe(true);
  });
});

describe("diffHosts", () => {
  it("marks listed and missing hosts", () => {
    const rows = diffHosts(
      [
        { host: "listed.example.com", sources: ["app:x"] },
        { host: "missing.example.com", sources: ["provider:y"] },
      ],
      ["listed.example.com", "*.other.com"],
    );
    expect(rows[0]?.listed).toBe(true);
    expect(rows[1]?.listed).toBe(false);
  });

  it("merges sources when aggregating before diff", () => {
    const rows = diffHosts(
      [{ host: "one.example.com", sources: ["app:a", "app:b"] }],
      ["one.example.com"],
    );
    expect(rows[0]?.sources).toEqual(["app:a", "app:b"]);
    expect(rows[0]?.listed).toBe(true);
  });
});
