import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../app.js";
import type { ProxiedOriginCredential } from "../registry/projection.js";
import { testEdgeConfig } from "../test/config.js";
import { FakeBlobReader, FakeRegistry, registryEntry } from "../test/fakes.js";
import { buildRegistrationSnippet, buildServiceWorkerScript } from "./serviceWorker.js";

/**
 * The offline capability (ADR-0035). The adversarial half of this lives here
 * rather than in `auth/adversarial.test.ts` because every assertion is about the
 * *serving* surface — but it is the same class of test: the platform-wide
 * service-worker ban exists to keep a worker away from the handoff token, and
 * these pin the exceptions that lifting it introduces.
 */

const OFFLINE = "apps/offline/1/";
const PLAIN = "apps/plain/1/";
const GONE = "apps/gone/1/";
const BOTH = "apps/both/1/";
const HTML = "<!doctype html><html><head></head><body>hi</body></html>";
const SHELL = "<!doctype html><html><head></head><body>shell</body></html>";

const H = (slug: string) => ({ host: `${slug}.local.helix.azxlabs.io` });

/** The worker URL a registration actually uses — the scope rides in the query. */
const SW_URL = "/_helix/sw.js?scope=%2Fapp%2F";

let app: FastifyInstance;
beforeAll(async () => {
  const blob = new FakeBlobReader();
  // An offline app is served from its scope, so its bundle nests under it and
  // has no root index.html — exactly the layout the SPA fallback must handle.
  blob.set(`${OFFLINE}app/index.html`, {
    body: SHELL,
    contentType: "text/html; charset=utf-8",
    etag: '"s1"',
  });
  blob.set(`${OFFLINE}app/main.js`, { body: "console.log(1)", contentType: "text/javascript" });
  blob.set(`${PLAIN}index.html`, {
    body: HTML,
    contentType: "text/html; charset=utf-8",
    etag: '"h2"',
  });
  blob.set(`${BOTH}app/index.html`, { body: SHELL, contentType: "text/html; charset=utf-8" });

  const registry = new FakeRegistry([
    registryEntry({
      appId: "a1",
      slug: "offline",
      blobPrefix: OFFLINE,
      offline: { scope: "/app/" },
    }),
    registryEntry({ appId: "a2", slug: "plain", blobPrefix: PLAIN }),
    registryEntry({
      appId: "a3",
      slug: "gone",
      blobPrefix: GONE,
      archived: true,
      offline: { scope: "/app/" },
    }),
    // The pair that motivated inlining: offline + the fetch shim.
    registryEntry({
      appId: "a5",
      slug: "both",
      blobPrefix: BOTH,
      offline: { scope: "/app/" },
      fetch: {
        shim: true,
        connections: new Map<string, ProxiedOriginCredential>([
          ["https://api.github.com", { kind: "keyless" }],
        ]),
        requestsPerDay: null,
      },
    }),
  ]);
  app = buildApp({ config: testEdgeConfig({ allowUnauthenticated: true }), registry, blob });
  await app.ready();
});
afterAll(async () => {
  await app.close();
});

describe("buildServiceWorkerScript", () => {
  const js = buildServiceWorkerScript({ scope: "/app/", cacheVersion: "apps/x/7/" });

  it("bakes in the scope and versions the cache by blob prefix", () => {
    // Version-keyed cache is what preserves the ADR-0018 pointer flip: a
    // promote changes these bytes, so the browser installs a new worker and
    // activate drops the stale cache.
    expect(js).toContain('"/app/"');
    expect(js).toContain('"helix:apps/x/7/"');
  });

  it("refuses to handle the platform namespaces", () => {
    expect(js).toContain('"/_auth/"');
    expect(js).toContain('"/_api/"');
    expect(js).toContain('"/_helix/"');
  });

  it("is network-first for navigations, and never reads the global cache index", () => {
    expect(js).toContain('request.mode === "navigate"');
    // Reads go through `lookup()` → `caches.open(CACHE).match()`. The global
    // `caches.match()` searches EVERY cache on the origin including the app's
    // own, which would make an app-written entry unshippable. Behaviour is
    // covered in serviceWorkerRuntime.test.ts; this pins the shape.
    expect(js).toContain("lookup(request)");
    // Comments stripped — the worker's own doc comment names the API it avoids.
    const code = js.replace(/^\s*\/\/.*$/gm, "");
    expect(code).not.toContain("caches.match(");
  });

  it("answers helix:status so apps never depend on the cache-name format", () => {
    expect(js).toContain('"helix:status"');
    expect(js).toContain('"helix:precache"');
  });
});

describe("buildRegistrationSnippet", () => {
  it("bakes the scope into the script URL so the tombstone can install later", () => {
    // The max-scope test runs on EVERY update check, so a response without
    // `Service-Worker-Allowed` fails with SecurityError. When the grant is gone
    // there is no scope left to look up — the URL has to carry it.
    const js = buildRegistrationSnippet("/app/");
    expect(js).toContain('"/_helix/sw.js?scope=%2Fapp%2F"');
    expect(js).toContain("scope: SCOPE");
    expect(js).toContain('updateViaCache: "none"');
  });

  it("hands the worker what the first visit already loaded, gated on load", () => {
    // Without the backfill the registering page's own requests bypass the
    // worker and offline boot needs a SECOND visit. Gating on `load` rather
    // than `ready` matters: `ready` resolves after a purely local
    // install→activate, routinely beating the page's own subresources, and
    // resource timings only appear once a resource has finished.
    const js = buildRegistrationSnippet("/app/");
    expect(js).toContain('getEntriesByType("resource")');
    expect(js).toContain('addEventListener("load"');
    expect(js).toContain('readyState === "complete"');
    // The document travels separately — it needs an HTML Accept downstream.
    expect(js).toContain("document: location.href");
  });

  it("stays inlinable and separately named in devtools", () => {
    const js = buildRegistrationSnippet("/app/");
    expect(js).not.toContain("</script");
    expect(js).toContain("//# sourceURL=helix/sw-register.js");
  });
});

describe("GET /_helix/sw.js", () => {
  it("serves the worker for a granted app, scoped and under the app CSP", async () => {
    const res = await app.inject({ url: SW_URL, headers: H("offline") });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toContain("text/javascript");
    // The one route on the platform that widens worker scope.
    expect(res.headers["service-worker-allowed"]).toBe("/app/");
    // For a worker the CSP on the SCRIPT governs the worker's own context —
    // served bare, its fetch() would escape `connect-src 'self'`.
    expect(res.headers["content-security-policy"]).toContain("connect-src 'self'");
    expect(res.headers["content-security-policy"]).toContain("img-src 'self' data: blob:");
    expect(res.headers["content-security-policy"]).toContain("object-src 'none'");
    expect(res.headers["content-security-policy-report-only"]).toBeUndefined();
    // Always revalidated, so a withdrawn grant converges on the next check.
    expect(res.headers["cache-control"]).toBe("no-cache");
    expect(res.body).toContain("helix:apps/offline/1/");
  });

  it("tombstones an app with no grant — WITH the scope header, or it can't install", async () => {
    // The header is the whole fix. A tombstone served without it fails the
    // max-scope test on the update check and is never installed, leaving the
    // worker it was meant to kill in place. An earlier version of this test
    // asserted the header's ABSENCE and so pinned that bug.
    const res = await app.inject({ url: SW_URL, headers: H("plain") });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("self.registration.unregister()");
    expect(res.headers["service-worker-allowed"]).toBe("/app/");
  });

  it("tombstones an archived app, still scoped so the kill lands", async () => {
    const res = await app.inject({ url: SW_URL, headers: H("gone") });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("self.registration.unregister()");
    expect(res.headers["service-worker-allowed"]).toBe("/app/");
  });

  it("tombstones an unknown slug rather than leaking its absence", async () => {
    const res = await app.inject({ url: SW_URL, headers: H("nope") });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("self.registration.unregister()");
  });

  it("tombstones — and does not widen — when the claimed scope is not the granted one", async () => {
    // Otherwise the URL param would be a way to get a working worker at an
    // arbitrary prefix without ever passing the approval gate.
    const res = await app.inject({
      url: "/_helix/sw.js?scope=%2Felsewhere%2F",
      headers: H("offline"),
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("self.registration.unregister()");
    expect(res.headers["service-worker-allowed"]).toBe("/elsewhere/");
    expect(res.headers["content-security-policy"]).toBeUndefined();
    expect(res.headers["content-security-policy-report-only"]).toBeUndefined();
  });

  const ILLEGAL_CLAIMS = ["%2F", "%2F_auth%2F", "%2Fapp", "%2Fapp%2F%2E%2E%2F", "%2Fapp%2F%2F"];

  it("never echoes an illegal claimed scope into the header", async () => {
    // On a granted app an illegal claim falls back to the *granted* scope,
    // which is safe — that value came from the manifest. What must never
    // happen is the claim itself reaching the header.
    for (const claimed of ILLEGAL_CLAIMS) {
      const res = await app.inject({
        url: `/_helix/sw.js?scope=${claimed}`,
        headers: H("offline"),
      });
      expect(res.statusCode, claimed).toBe(200);
      expect(res.headers["service-worker-allowed"], claimed).toBe("/app/");
      expect(res.body, claimed).toContain("self.registration.unregister()");
    }
  });

  it("emits no header at all for an illegal claim with no grant to fall back to", async () => {
    for (const claimed of ILLEGAL_CLAIMS) {
      const res = await app.inject({
        url: `/_helix/sw.js?scope=${claimed}`,
        headers: H("plain"),
      });
      expect(res.headers["service-worker-allowed"], claimed).toBeUndefined();
      expect(res.body, claimed).toContain("self.registration.unregister()");
    }
  });

  it("kills a legacy registration that predates the scope param", async () => {
    // No `?scope=` — a worker registered before the scope moved into the URL.
    // It still gets a header (from the grant), so the tombstone can install and
    // the stale worker dies; the injected snippet then re-registers at the
    // current URL. Without the fallback such a registration is unkillable.
    const res = await app.inject({ url: "/_helix/sw.js", headers: H("offline") });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("self.registration.unregister()");
    expect(res.headers["service-worker-allowed"]).toBe("/app/");
  });

  it("refuses a repeated scope param rather than picking an arm", async () => {
    // `?scope=/app/&scope=/` is someone probing; resolving to either arm is a
    // worse answer than none. With no usable claim it falls back to the grant.
    const granted = await app.inject({
      url: "/_helix/sw.js?scope=%2Fapp%2F&scope=%2F",
      headers: H("offline"),
    });
    expect(granted.headers["service-worker-allowed"]).toBe("/app/");
    expect(granted.body).toContain("self.registration.unregister()");

    const none = await app.inject({
      url: "/_helix/sw.js?scope=%2Fapp%2F&scope=%2F",
      headers: H("plain"),
    });
    expect(none.headers["service-worker-allowed"]).toBeUndefined();
  });

  it("404s on a platform host", async () => {
    const res = await app.inject({ url: SW_URL, headers: { host: "localhost:8080" } });
    expect(res.statusCode).toBe(404);
  });
});

describe("a registry blip must not destroy the fleet's offline support", () => {
  // Serving a tombstone is irreversible client-side: it deletes every `helix:*`
  // cache and unregisters. The edge accepts traffic before the projection's
  // first load succeeds (`server.ts` — a down DB retries rather than blocking
  // boot), so without this guard a fleet restart during a Postgres blip would
  // wipe offline support on every device, exactly when the platform is least
  // healthy. A failed update check leaves the working worker installed instead.
  function coldEdge(): FastifyInstance {
    return buildApp({
      config: testEdgeConfig({ allowUnauthenticated: true }),
      registry: new FakeRegistry([], { loaded: false }),
      blob: new FakeBlobReader(),
    });
  }

  it("503s the worker route instead of tombstoning when the projection is cold", async () => {
    const cold = coldEdge();
    await cold.ready();
    const res = await cold.inject({ url: SW_URL, headers: H("offline") });
    expect(res.statusCode).toBe(503);
    expect(res.body).not.toContain("unregister");
    await cold.close();
  });

  it("503s the document too, so no page is served without its registration", async () => {
    // The registration is inlined, so its "never answer off an unloaded
    // projection" rule is the asset handler's 503 — there is no separate route
    // left to get this wrong.
    const cold = coldEdge();
    await cold.ready();
    const res = await cold.inject({
      url: "/app/",
      headers: { ...H("offline"), accept: "text/html" },
    });
    expect(res.statusCode).toBe(503);
    await cold.close();
  });

  it("503s a granted app mid-promote rather than unregistering over a race", async () => {
    // Row present, grant intact, nothing live yet — transient, not a revocation.
    const mid = buildApp({
      config: testEdgeConfig({ allowUnauthenticated: true }),
      registry: new FakeRegistry([
        registryEntry({
          appId: "a4",
          slug: "offline",
          blobPrefix: null,
          offline: { scope: "/app/" },
        }),
      ]),
      blob: new FakeBlobReader(),
    });
    await mid.ready();
    const res = await mid.inject({ url: SW_URL, headers: H("offline") });
    expect(res.statusCode).toBe(503);
    expect(res.body).not.toContain("unregister");
    await mid.close();
  });
});

describe("the ban survives, and Service-Worker-Allowed never leaks", () => {
  it("still 403s a registration fetch for an app asset", async () => {
    const res = await app.inject({
      url: "/app/main.js",
      headers: { ...H("offline"), "service-worker": "script" },
    });
    expect(res.statusCode).toBe(403);
  });

  it("leaves no other registrable script under /_helix/", async () => {
    // The shim and the registration snippet used to be served from here, and
    // each had to refuse a registration fetch of its own. Both are inlined now,
    // so `/_helix/sw.js` is the only script left under the prefix and the
    // question answers itself: everything else is a reserved-namespace 404.
    for (const url of ["/_helix/fetch-shim.js", "/_helix/sw-register.js", "/_helix/"]) {
      const res = await app.inject({
        url,
        headers: { ...H("offline"), "service-worker": "script" },
      });
      expect(res.statusCode, url).toBe(404);
    }
  });

  it("emits Service-Worker-Allowed on the worker route and nowhere else", async () => {
    for (const url of ["/app/", "/app/index.html", "/app/main.js", "/_helix/sw-register.js"]) {
      const res = await app.inject({ url, headers: { ...H("offline"), accept: "text/html" } });
      expect(res.headers["service-worker-allowed"], url).toBeUndefined();
    }
  });
});

describe("registration injection", () => {
  it("inlines the registration into a granted app's HTML, without an etag", async () => {
    // A navigation to the scope root: `normalizeRequestPath` drops the trailing
    // slash, so `/app/` resolves through the HTML fallback below — which is why
    // the Accept header (which every real navigation sends) matters here.
    const res = await app.inject({
      url: "/app/",
      headers: { ...H("offline"), accept: "text/html" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("<head><script>(function () {");
    expect(res.body).toContain("navigator.serviceWorker.register");
    // The worker URL is the one `/_helix/` reference left, and it is a string
    // inside the snippet rather than a resource the document has to fetch.
    expect(res.body).toContain('"/_helix/sw.js?scope=%2Fapp%2F"');
    expect(res.body).not.toContain("<script src=");
    expect(res.headers.etag).toBeUndefined(); // injected bytes ≠ blob etag
  });

  it("does not inject for an app without the grant (and keeps its etag)", async () => {
    const res = await app.inject({ url: "/", headers: H("plain") });
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe(HTML);
    expect(res.headers.etag).toBe('"h2"');
  });

  it("inlines BOTH snippets, shim first, for an app holding both grants", async () => {
    // The regression test for the bug that motivated inlining: with the shim
    // served from `/_helix/*` — which the worker deliberately never caches — an
    // offline cold boot left `fetch` unpatched and proxied calls died on CSP.
    // Inline, both snippets are inside the cached document.
    const res = await app.inject({
      url: "/app/",
      headers: { ...H("both"), accept: "text/html" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).not.toContain("<script src=");
    const shimAt = res.body.indexOf("XMLHttpRequest.prototype.open");
    const regAt = res.body.indexOf("navigator.serviceWorker.register");
    expect(shimAt).toBeGreaterThan(-1);
    expect(regAt).toBeGreaterThan(-1);
    // Shim first: it has to patch `fetch` before anything else on the page runs.
    expect(shimAt).toBeLessThan(regAt);
  });
});

describe("scope-aware SPA fallback", () => {
  it("falls back to the scope's shell for a deep link inside the scope", async () => {
    // The bundle has no ROOT index.html — falling back there would 404 every
    // client-side route of an app served from a prefix.
    const res = await app.inject({
      url: "/app/review/123",
      headers: { ...H("offline"), accept: "text/html" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("shell");
  });

  it("does not rescue a deep link outside the scope", async () => {
    const res = await app.inject({
      url: "/elsewhere/x",
      headers: { ...H("offline"), accept: "text/html" },
    });
    expect(res.statusCode).toBe(404);
  });

  it("leaves a non-offline app's root fallback alone", async () => {
    const res = await app.inject({
      url: "/deep/link",
      headers: { ...H("plain"), accept: "text/html" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain("hi");
  });

  it("resolves the scope root only for an HTML-accepting request", async () => {
    // This is why the backfill sends the document with an HTML `Accept` and
    // subresources without one (review #4). `normalizeRequestPath` drops the
    // trailing slash, so `/app/` looks for a blob named `app`, misses, and only
    // the SPA fallback rescues it — and that fallback is gated on Accept. A
    // precache request built with the default `*/*` therefore 404s, which is
    // not storable, so the one URL cold boot depends on never gets cached.
    const html = await app.inject({
      url: "/app/",
      headers: { ...H("offline"), accept: "text/html,application/xhtml+xml,*/*" },
    });
    expect(html.statusCode).toBe(200);
    expect(html.body).toContain("shell");

    const any = await app.inject({ url: "/app/", headers: { ...H("offline"), accept: "*/*" } });
    expect(any.statusCode).toBe(404);
  });

  it("still hard-404s an asset miss inside the scope", async () => {
    const res = await app.inject({ url: "/app/missing.js", headers: H("offline") });
    expect(res.statusCode).toBe(404);
  });
});
