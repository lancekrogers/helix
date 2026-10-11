import { describe, expect, it } from "vitest";
import type { FastifyRequest } from "fastify";
import { controlOrigin, publicOrigin } from "../config.js";
import {
  isSameOrigin,
  makeSameOriginCheck,
  resolveAppForAuth,
  validateReturnPath,
  visibilityAllows,
} from "./validate.js";
import { splitEdgeConfig, testAuthConfig } from "../test/config.js";
import { FakeRegistry, registryEntry } from "../test/fakes.js";

describe("validateReturnPath (the open-redirect corpus)", () => {
  it("accepts plain same-origin paths, preserving query and fragment", () => {
    expect(validateReturnPath("/")).toBe("/");
    expect(validateReturnPath("/page")).toBe("/page");
    expect(validateReturnPath("/a/b?x=1&y=2")).toBe("/a/b?x=1&y=2");
    expect(validateReturnPath("/a#sec")).toBe("/a#sec");
    expect(validateReturnPath("/with%20escapes")).toBe("/with%20escapes");
  });

  it("defaults absent to /", () => {
    expect(validateReturnPath(undefined)).toBe("/");
    expect(validateReturnPath("")).toBe("/");
  });

  it("rejects absolute URLs and scheme-relative escapes", () => {
    for (const evil of [
      "http://evil.example/",
      "https://evil.example/",
      "//evil.example/",
      "//evil.example",
      "/\\evil.example",
      "\\evil.example",
      "\\\\evil.example",
      "javascript:alert(1)",
      "data:text/html,x",
      "//auth.local.helix.azxlabs.io/x",
      "https://helix-apps.localhost/",
      "/\\helix-apps.localhost",
      "/%0d%0aSet-Cookie:x=1",
      "/\t/evil.example",
    ]) {
      expect(validateReturnPath(evil), evil).toBeNull();
    }
  });

  it("rejects missing-slash and dot-relative paths", () => {
    expect(validateReturnPath("page")).toBeNull();
    expect(validateReturnPath("../up")).toBeNull();
    expect(validateReturnPath("./here")).toBeNull();
  });

  /**
   * The session gate sets `rd = validateReturnPath(req.raw.url)` on any
   * unauthenticated request, so a return path that lands on `/_api/*` lets the
   * SSO flow itself walk a *signed-out* victim through login and deposit them on
   * the gateway as a top-level navigation. Checked post-resolution so traversal
   * and case variants can't slip past.
   */
  it("rejects /_api/* return paths — SSO must not deposit a user on the gateway", () => {
    for (const evil of [
      "/_api",
      "/_api/",
      "/_api/fetch/https://api.example.com/x",
      "/_api/data/user/k",
      "/_API/fetch/x",
      "/x/../_api/fetch/y",
    ]) {
      expect(validateReturnPath(evil), evil).toBeNull();
    }
    // Not over-broad: a path that merely starts with the same letters is fine.
    expect(validateReturnPath("/_apifoo")).toBe("/_apifoo");
  });

  it("rejects control characters and overlong paths", () => {
    expect(validateReturnPath("/a\r\nLocation: https://evil")).toBeNull();
    expect(validateReturnPath("/a\0b")).toBeNull();
    expect(validateReturnPath("/a\tb")).toBeNull();
    expect(validateReturnPath(`/${"a".repeat(2000)}`)).toBeNull();
  });

  it("keeps encoded slashes inert (they stay path, not authority)", () => {
    // %2F%2F decodes to // but URL resolution keeps it on-origin as a path.
    expect(validateReturnPath("/%2F%2Fevil.example")).toBe("/%2F%2Fevil.example");
  });
});

describe("resolveAppForAuth", () => {
  const registry = new FakeRegistry([
    registryEntry({ slug: "demo", blobPrefix: "apps/x/1/" }),
    registryEntry({ slug: "gone", archived: true }),
    registryEntry({ slug: "team", visibilityMode: "group", visibilityGroupIds: ["eng-team"] }),
    registryEntry({ slug: "open", visibilityMode: "public" }),
    registryEntry({ slug: "gated", visibilityMode: "password" }),
  ]);

  it("resolves private, group, and password apps (password apps also admit SSO)", () => {
    expect(resolveAppForAuth(registry, "demo").kind).toBe("ok");
    expect(resolveAppForAuth(registry, "team").kind).toBe("ok");
    expect(resolveAppForAuth(registry, "gated").kind).toBe("ok");
  });

  it("treats unknown, invalid and archived slugs identically", () => {
    expect(resolveAppForAuth(registry, "nope").kind).toBe("unknown");
    expect(resolveAppForAuth(registry, undefined).kind).toBe("unknown");
    expect(resolveAppForAuth(registry, "Not A Slug!").kind).toBe("unknown");
    expect(resolveAppForAuth(registry, "gone").kind).toBe("unknown");
  });

  it("treats reserved platform slugs as unknown (no handoff for unservable apps)", () => {
    for (const slug of ["auth", "portal", "api", "www"]) {
      expect(resolveAppForAuth(registry, slug).kind).toBe("unknown");
    }
  });

  it("fails closed on public visibility (no session to mint)", () => {
    expect(resolveAppForAuth(registry, "open").kind).toBe("unsupported-mode");
  });

  it("reports an unloaded registry", () => {
    const empty = new FakeRegistry([], { loaded: false });
    expect(resolveAppForAuth(empty, "demo").kind).toBe("registry-unavailable");
  });
});

describe("visibilityAllows", () => {
  it("internal admits any authenticated user", () => {
    expect(visibilityAllows(registryEntry({ slug: "a" }), [])).toBe(true);
  });

  it("group requires one of the configured groups in the snapshot", () => {
    const entry = registryEntry({ slug: "a", visibilityMode: "group", visibilityGroupIds: ["g1"] });
    expect(visibilityAllows(entry, ["g1", "g2"])).toBe(true);
    expect(visibilityAllows(entry, ["g2"])).toBe(false);
    expect(visibilityAllows(entry, [])).toBe(false);
  });

  // Any-of, not all-of (ADR-0040 §5) — "engineering OR product". Getting this
  // backwards would be a silent lockout for everyone not in every listed group,
  // which reads as "the feature doesn't work" rather than as an authz bug, so it
  // is worth pinning from more than one direction.
  it("group is any-of: membership in exactly one listed group is enough", () => {
    const entry = registryEntry({
      slug: "a",
      visibilityMode: "group",
      visibilityGroupIds: ["eng", "product", "design"],
    });
    expect(visibilityAllows(entry, ["eng"])).toBe(true);
    expect(visibilityAllows(entry, ["design"])).toBe(true); // last listed, not just first
    expect(visibilityAllows(entry, ["product", "unrelated"])).toBe(true);
    expect(visibilityAllows(entry, ["eng", "product", "design"])).toBe(true);
    expect(visibilityAllows(entry, ["sales", "unrelated"])).toBe(false);
    expect(visibilityAllows(entry, [])).toBe(false);
  });

  it("a group app with no groups admits nobody (misconfig fails closed)", () => {
    const entry = registryEntry({ slug: "a", visibilityMode: "group", visibilityGroupIds: [] });
    expect(visibilityAllows(entry, ["anything"])).toBe(false);
    expect(visibilityAllows(entry, [])).toBe(false);
  });

  // The projection normalizes the array column, but the gate is the last line
  // and must not depend on that having happened — a stale replica, a hand-run
  // SQL fix, or a future writer that skips the mapper all reach here directly.
  it("survives a non-array group field without admitting anyone", () => {
    const entry = registryEntry({ slug: "a", visibilityMode: "group" });
    for (const bad of [null, undefined, "g1", 42, {}]) {
      const off = { ...entry, visibilityGroupIds: bad as never };
      expect(() => visibilityAllows(off, ["g1"])).not.toThrow();
      expect(visibilityAllows(off, ["g1"])).toBe(false);
    }
  });

  it("a password session (groups irrelevant) is allowed — the password was the proof", () => {
    expect(visibilityAllows(registryEntry({ slug: "a", visibilityMode: "password" }), [])).toBe(
      true,
    );
  });

  it("public never passes the session gate (it has no session)", () => {
    expect(visibilityAllows(registryEntry({ slug: "a", visibilityMode: "public" }), [])).toBe(
      false,
    );
  });

  // The fall-through is load-bearing, so pin it. A mode this gate does not
  // understand can reach it two ways: a label added to the enum before the gate
  // learns it, or a replica still running older code after a rename (exactly
  // what the `private` → `internal` rename does mid-rollout). Both must deny.
  // This is also what makes reclaiming the name `private` for a real owner-only
  // mode safe rather than dangerous — an unimplemented mode serves nobody
  // instead of everybody.
  it("denies a visibility mode it does not recognise (fails closed)", () => {
    // Deliberately off-contract: the union has no such member, which is the
    // point — this asserts the runtime behaviour the types can't guarantee
    // across a version skew.
    const entry = registryEntry({ slug: "a" });
    const unknown = { ...entry, visibilityMode: "private" as never };
    expect(visibilityAllows(unknown, [])).toBe(false);
    expect(visibilityAllows(unknown, ["any", "groups"])).toBe(false);
    expect(visibilityAllows({ ...entry, visibilityMode: "" as never }, [])).toBe(false);
  });
});

describe("isSameOrigin / makeSameOriginCheck (split layout)", () => {
  const cfg = splitEdgeConfig({ auth: testAuthConfig() });
  const entry = registryEntry({ slug: "appa" });

  it("accepts only the apps-domain origin for the slug", () => {
    expect(isSameOrigin(publicOrigin(cfg, "appa"), cfg, "appa")).toBe(true);
    expect(isSameOrigin(controlOrigin(cfg, "auth"), cfg, "appa")).toBe(false);
    expect(isSameOrigin(publicOrigin(cfg, "appb"), cfg, "appa")).toBe(false);
    expect(isSameOrigin(`https://appa.${cfg.controlDomain}:8080`, cfg, "appa")).toBe(false);
  });

  it("makeSameOriginCheck honours Fetch Metadata and refuses worker loads", () => {
    const check = makeSameOriginCheck(cfg);
    const good = {
      headers: {
        origin: publicOrigin(cfg, "appa"),
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
      },
    } as FastifyRequest;
    expect(check(good, entry)).toBe(true);

    const cross = {
      headers: {
        origin: publicOrigin(cfg, "appa"),
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "cors",
      },
    } as FastifyRequest;
    expect(check(cross, entry)).toBe(false);

    const worker = {
      headers: {
        origin: publicOrigin(cfg, "appa"),
        "sec-fetch-site": "same-origin",
        "sec-fetch-dest": "worker",
      },
    } as FastifyRequest;
    expect(check(worker, entry)).toBe(false);
  });
});
