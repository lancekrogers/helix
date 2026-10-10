import { describe, expect, it } from "vitest";
import { SPLIT_APPS_DOMAIN, SPLIT_CONTROL_DOMAIN } from "../test/config.js";
import { classifyHost } from "./hosts.js";

const BASE = "local.helix.azxlabs.io";

describe("classifyHost", () => {
  it("classifies a single-label subdomain as an app host", () => {
    expect(classifyHost("demo.local.helix.azxlabs.io", BASE)).toEqual({
      kind: "app",
      slug: "demo",
    });
  });

  it("strips the port and lowercases", () => {
    expect(classifyHost("Demo.Local.Helix.AzxLabs.Io:8080", BASE)).toEqual({
      kind: "app",
      slug: "demo",
    });
  });

  it("classifies the apex domain as platform", () => {
    expect(classifyHost("local.helix.azxlabs.io", BASE)).toEqual({ kind: "platform" });
    expect(classifyHost("local.helix.azxlabs.io:8080", BASE)).toEqual({ kind: "platform" });
  });

  it("classifies multi-label subdomains as platform", () => {
    expect(classifyHost("a.b.local.helix.azxlabs.io", BASE)).toEqual({ kind: "platform" });
  });

  it("classifies unrelated hosts, localhost and IPs as platform", () => {
    expect(classifyHost("localhost:8080", BASE)).toEqual({ kind: "platform" });
    expect(classifyHost("127.0.0.1:8080", BASE)).toEqual({ kind: "platform" });
    expect(classifyHost("example.com", BASE)).toEqual({ kind: "platform" });
    expect(classifyHost("notlocal.helix.azxlabs.io", BASE)).toEqual({ kind: "platform" });
    expect(classifyHost("[::1]:8080", BASE)).toEqual({ kind: "platform" });
    expect(classifyHost(undefined, BASE)).toEqual({ kind: "platform" });
  });

  it("classifies the auth host as its own kind", () => {
    expect(classifyHost("auth.local.helix.azxlabs.io", BASE)).toEqual({ kind: "auth" });
    expect(classifyHost("Auth.local.helix.azxlabs.io:8443", BASE)).toEqual({ kind: "auth" });
    // Only an exact label on the base domain — never nested or elsewhere.
    expect(classifyHost("auth.evil.com", BASE)).toEqual({ kind: "platform" });
    expect(classifyHost("a.auth.local.helix.azxlabs.io", BASE)).toEqual({ kind: "platform" });
  });

  it("reserves platform subdomains", () => {
    for (const label of ["portal", "api", "www"]) {
      expect(classifyHost(`${label}.local.helix.azxlabs.io`, BASE)).toEqual({ kind: "platform" });
    }
  });

  it("rejects labels that are not valid slugs", () => {
    expect(classifyHost("-bad.local.helix.azxlabs.io", BASE)).toEqual({ kind: "platform" });
    expect(classifyHost("bad-.local.helix.azxlabs.io", BASE)).toEqual({ kind: "platform" });
    expect(classifyHost(".local.helix.azxlabs.io", BASE)).toEqual({ kind: "platform" });
  });

  it("honors a configurable base domain", () => {
    expect(classifyHost("demo.azx.helix.azxlabs.io", "azx.helix.azxlabs.io")).toEqual({
      kind: "app",
      slug: "demo",
    });
    expect(classifyHost("demo.local.helix.azxlabs.io", "azx.helix.azxlabs.io")).toEqual({
      kind: "platform",
    });
  });
});

describe("split layout", () => {
  const CONTROL = SPLIT_CONTROL_DOMAIN;
  const APPS = SPLIT_APPS_DOMAIN;

  function classify(host: string) {
    return classifyHost(host, APPS, CONTROL);
  }

  it("pins auth on the control domain only", () => {
    expect(classify(`auth.${CONTROL}`)).toEqual({ kind: "auth" });
    expect(classify(`auth.${APPS}`)).toEqual({ kind: "platform" });
    for (const label of ["portal", "www", "api"]) {
      expect(classify(`${label}.${APPS}`)).toEqual({ kind: "platform" });
    }
    expect(classify(`demo.${APPS}`)).toEqual({ kind: "app", slug: "demo" });
    expect(classify(`demo.${CONTROL}`)).toEqual({ kind: "platform" });
    expect(classify(APPS)).toEqual({ kind: "platform" });
    expect(classify(CONTROL)).toEqual({ kind: "platform" });
    expect(classify(`dev-api.${APPS}`)).toEqual({ kind: "app", slug: "dev-api" });
  });

  it("legacy-app on the control suffix when redirect is enabled", () => {
    expect(classifyHost(`demo.${CONTROL}`, APPS, CONTROL, true)).toEqual({
      kind: "legacy-app",
      slug: "demo",
    });
    expect(classifyHost(`demo.${CONTROL}`, APPS, CONTROL, false)).toEqual({ kind: "platform" });
    expect(classifyHost(`auth.${CONTROL}`, APPS, CONTROL, true)).toEqual({ kind: "auth" });
    for (const label of ["portal", "api", "www", "dev-api"]) {
      expect(classifyHost(`${label}.${CONTROL}`, APPS, CONTROL, true)).toEqual({
        kind: "platform",
      });
    }
    expect(classifyHost(`a.b.${CONTROL}`, APPS, CONTROL, true)).toEqual({ kind: "platform" });
    expect(classifyHost(`demo.${APPS}`, APPS, CONTROL, true)).toEqual({
      kind: "app",
      slug: "demo",
    });
    expect(classifyHost(`demo.${CONTROL}`, APPS, APPS, true)).toEqual({ kind: "platform" });
    expect(classifyHost(`demo.apps.${CONTROL}`, APPS, CONTROL, true)).toEqual({ kind: "platform" });
  });

  it("delegated-subdomain: control parent of apps", () => {
    const parent = "helix.customer.test";
    const apps = "apps.helix.customer.test";
    expect(classifyHost(`auth.${parent}`, apps, parent)).toEqual({ kind: "auth" });
    expect(classifyHost(`auth.${apps}`, apps, parent)).toEqual({ kind: "platform" });
    expect(classifyHost(`demo.${apps}`, apps, parent)).toEqual({ kind: "app", slug: "demo" });
  });

  it("rejects lookalike auth hosts", () => {
    const cases = [
      `xauth.${CONTROL}`,
      `a.auth.${CONTROL}`,
      `auth.${CONTROL}.evil.example`,
      `auth.${CONTROL}.`,
      `evil.example:@auth.${CONTROL}`,
      `evil.example@app.${APPS}`,
      `auth.${CONTROL}/path-in-host`,
      undefined,
      "[::1]:8080",
      "",
    ];
    for (const host of cases) {
      expect(classifyHost(host, APPS, CONTROL)).toEqual({ kind: "platform" });
    }
    expect(classifyHost(`AUTH.${CONTROL}`, APPS, CONTROL)).toEqual({ kind: "auth" });
    expect(classifyHost(`auth.${CONTROL}:8443`, APPS, CONTROL)).toEqual({ kind: "auth" });
    expect(classifyHost(`auth.${CONTROL}:`, APPS, CONTROL)).toEqual({ kind: "auth" });
  });
});
