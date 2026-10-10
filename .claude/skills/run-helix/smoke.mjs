#!/usr/bin/env node
/**
 * Helix platform smoke test — boots all three planes plus the dev IdP and the
 * portal SPA, then drives them the way a user (or an app) actually would.
 *
 *   node .claude/skills/run-helix/smoke.mjs [options]
 *
 * Exit code 0 = everything the environment supports passed. Anything skipped
 * is reported as SKIP, never folded into the pass count.
 *
 * See ./SKILL.md for prerequisites and the flag reference.
 *
 * Split-domain dev (`HELIX_APPS_DOMAIN`): use `--only split-tls` until the edge and
 * portal read the control domain; full login is not expected to work before that.
 */
import { spawn, spawnSync } from "node:child_process";
import dns from "node:dns";
import tls from "node:tls";
import { createRequire } from "node:module";
import {
  copyFileSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import * as httpsModule from "node:https";
import * as httpModule from "node:http";
import { launchBrowser, findChrome } from "./cdp.mjs";
import { resolveStack } from "../../../scripts/stack-env.mjs";
import { ensureDatabase } from "../../../scripts/ensure-db.mjs";

const ROOT = new URL("../../../", import.meta.url).pathname.replace(/\/$/, "");
const SMOKE_FIXTURES = join(ROOT, ".claude/skills/run-helix/fixtures");
const CA = join(ROOT, ".devcontainer/certs/caroot/rootCA.pem");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The edge serves https with a mkcert cert. Trust that CA process-wide rather
// than disabling verification, so a genuine TLS regression still fails.
if (existsSync(CA) && !process.env.NODE_EXTRA_CA_CERTS) {
  process.env.NODE_EXTRA_CA_CERTS = CA;
  const r = spawnSync(process.execPath, [process.argv[1], ...process.argv.slice(2)], {
    stdio: "inherit",
    env: process.env,
  });
  process.exit(r.status ?? 1);
}

// ── options ───────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const only = argv.includes("--only") ? argv[argv.indexOf("--only") + 1] : null;
const KEEP = has("--keep");
const NO_BROWSER = has("--no-browser");
const OUT = mkdtempSync(join(tmpdir(), "helix-smoke-"));

/**
 * This driver boots its OWN stack rather than borrowing the developer's.
 * The default offset moves every port, the database and the blob container off
 * the dev stack's, so a run can never kill `pnpm dev:*` or write to the dev
 * database. `--offset 0` opts back into the shared dev ports.
 */
const OFFSET = argv.includes("--offset")
  ? Number(argv[argv.indexOf("--offset") + 1])
  : Number(process.env.HELIX_PORT_OFFSET ?? 1000);
let STACK;
try {
  STACK = resolveStack({ offset: OFFSET });
} catch (err) {
  console.error(err.message);
  process.exit(2);
}
/** Env every service in THIS stack boots with. */
const SVC_ENV = { ...process.env, ...STACK.env };
const PORTS = Object.values(STACK.ports);

const GROUPS = ["idp", "portal", "edge", "egress", "spa", "browser", "cli", "split-tls"];

const SPLIT_CERT = join(ROOT, ".devcontainer/certs/local-helix-split.pem");
const SPLIT_KEY = join(ROOT, ".devcontainer/certs/local-helix-split-key.pem");
const MKCERT_SPLIT_CMD =
  "CAROOT=/workspace/.devcontainer/certs/caroot mkcert -cert-file /workspace/.devcontainer/certs/local-helix-split.pem " +
  "-key-file /workspace/.devcontainer/certs/local-helix-split-key.pem " +
  '"*.local.helix.azxlabs.io" local.helix.azxlabs.io "*.helix-apps.localhost" helix-apps.localhost "*.apps.local.helix.azxlabs.io" apps.local.helix.azxlabs.io';

const APPS_DOMAIN = STACK.appsDomain;
const CONTROL_DOMAIN = STACK.controlDomain;

// glibc does not resolve arbitrary *.localhost names, so never rely on getaddrinfo for the apps domain.
const isAppsHost = (h) => h === APPS_DOMAIN || h.endsWith(`.${APPS_DOMAIN}`);
const loopbackLookup = (hostname, opts, cb) => {
  if (!STACK.split || !isAppsHost(hostname)) return dns.lookup(hostname, opts, cb);
  return opts?.all ? cb(null, [{ address: "127.0.0.1", family: 4 }]) : cb(null, "127.0.0.1", 4);
};

/** @type {"undici-global-dispatcher" | "dns.lookup-patch" | null} */
let splitFetchMechanism = null;
if (STACK.split) {
  const require = createRequire(join(ROOT, "apps/edge/package.json"));
  const { Agent, setGlobalDispatcher } = require("undici");
  setGlobalDispatcher(new Agent({ connect: { lookup: loopbackLookup } }));
  splitFetchMechanism = "undici-global-dispatcher";
}
const wanted = (g) => !only || only === g;

// ── result tracking ───────────────────────────────────────────────────────
const results = [];
let currentGroup = "boot";
function group(g) {
  currentGroup = g;
}
async function check(name, fn) {
  try {
    const detail = await fn();
    results.push({ group: currentGroup, name, ok: true, detail });
    console.log(`  \x1b[32m✓\x1b[0m ${name}${detail ? `  \x1b[2m${detail}\x1b[0m` : ""}`);
  } catch (err) {
    results.push({ group: currentGroup, name, ok: false, detail: err.message });
    console.log(`  \x1b[31m✗\x1b[0m ${name}\n      \x1b[31m${err.message}\x1b[0m`);
  }
}
function skip(name, why) {
  results.push({ group: currentGroup, name, skipped: true, detail: why });
  console.log(`  \x1b[33m•\x1b[0m ${name}  \x1b[2mSKIP — ${why}\x1b[0m`);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
function eq(actual, expected, what) {
  assert(actual === expected, `${what}: expected ${expected}, got ${actual}`);
}

// ── service lifecycle ─────────────────────────────────────────────────────
// The edge's mkcert cert covers `*.local.helix.azxlabs.io` and the bare base
// domain — NOT `localhost`. Probing it on localhost fails TLS verification even
// though the socket is listening, so always address it by the base domain.
const BASE_DOMAIN = STACK.baseDomain;

const SERVICES = [
  {
    name: "dev-idp",
    script: "dev:idp",
    port: STACK.ports.idp,
    health: `http://localhost:${STACK.ports.idp}/.well-known/openid-configuration`,
  },
  {
    name: "portal",
    script: "dev:portal",
    port: STACK.ports.portal,
    health: `http://localhost:${STACK.ports.portal}/health`,
  },
  {
    name: "egress",
    script: "dev:egress",
    port: STACK.ports.egress,
    health: `http://localhost:${STACK.ports.egress}/health`,
  },
  {
    name: "edge",
    script: "dev:edge",
    port: STACK.ports.edge,
    health: `https://${BASE_DOMAIN}:${STACK.ports.edge}/health`,
  },
];
const procs = [];

/**
 * Release only THIS stack's ports. `pnpm dev:*` does not forward SIGTERM to its
 * tsx child, so a killed run can orphan a listener that the next run must clear
 * — but the list is the resolved stack, never the dev stack's literals, so at
 * any non-zero offset this cannot reach a developer's server.
 */
function freePorts() {
  spawnSync("node", [join(ROOT, "scripts/free-port.mjs"), ...PORTS.map(String)], {
    cwd: ROOT,
    stdio: "ignore",
  });
}

function startService(svc) {
  const log = join(OUT, `${svc.name}.log`);
  const fd = openSync(log, "a");
  // detached so we can SIGTERM the whole process group: `pnpm dev:x` spawns
  // tsx as a child and does not forward signals to it.
  const p = spawn("pnpm", [svc.script], {
    cwd: ROOT,
    stdio: ["ignore", fd, fd],
    detached: true,
    env: SVC_ENV,
  });
  procs.push({ ...svc, proc: p, log });
  return p;
}

async function waitHealthy(svc, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  let lastErr = "no response";
  while (Date.now() < deadline) {
    try {
      const r = await fetch(svc.health);
      if (r.ok) return true;
      lastErr = `HTTP ${r.status}`;
    } catch (e) {
      lastErr = e.message;
    }
    await sleep(500);
  }
  const tail = existsSync(join(OUT, `${svc.name}.log`))
    ? readFileSync(join(OUT, `${svc.name}.log`), "utf8")
        .split("\n")
        .slice(-12)
        .join("\n")
    : "";
  throw new Error(`${svc.name} never became healthy (${lastErr})\n--- log tail ---\n${tail}`);
}

function stopAll() {
  for (const { proc } of procs) {
    try {
      process.kill(-proc.pid, "SIGTERM");
    } catch {
      /* already dead */
    }
  }
  freePorts();
}

// ── http helpers ──────────────────────────────────────────────────────────
const TOKEN = process.env.PORTAL_DEV_TOKEN;
const auth = { Authorization: `Bearer ${TOKEN}` };
const PORTAL = `http://localhost:${STACK.ports.portal}`;
const EDGE = (host, path = "/") => `https://${host}.${BASE_DOMAIN}:${STACK.ports.edge}${path}`;
const EGRESS = `http://localhost:${STACK.ports.egress}`;

/**
 * Raw HTTPS request with EXACT header control.
 *
 * Node's global fetch() unconditionally sets `Sec-Fetch-Mode: cors` and
 * silently discards any value you pass for it. The edge's isNavigation()
 * treats that header as authoritative (apps/edge/src/auth/gate.ts), so a
 * top-level navigation is impossible to simulate with fetch() — you always
 * get the 401 subresource branch. node:https sends exactly what you give it.
 */
function rawGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === "https:" ? httpsModule : httpModule;
    const req = mod.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method: "GET",
        headers,
        lookup: loopbackLookup,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
          }),
        );
      },
    );
    req.on("error", reject);
    req.end();
  });
}

async function jget(url, init) {
  const r = await fetch(url, init);
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: r.status, headers: r.headers, body };
}

// ── seeding ───────────────────────────────────────────────────────────────
const CLI_BIN = join(ROOT, "packages/cli/dist/helix.js");
let cliBuild = null;

/** Build the CLI bundle once per run — both the seed and the cli group need it. */
function buildCli() {
  if (cliBuild) return cliBuild;
  const r = spawnSync("pnpm", ["--filter", "@azx-pbc/helix-cli", "build"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  assert(r.status === 0, `build failed:\n${(r.stderr || r.stdout || "").slice(-800)}`);
  const m = (r.stdout || "").match(/dist\/helix\.js\s+([\d.]+\s*\w+)/);
  cliBuild = m ? m[1] : "built";
  return cliBuild;
}

/**
 * Build the SPA. Must run **before the portal boots**, which is why it lives
 * here and not in `checkSpa()` with the assertions it feeds.
 *
 * `routes/spa.ts` registers @fastify/static with `wildcard: false`, and that
 * option makes the plugin glob the dist directory once at registration and
 * register one route per file it finds. A build that lands after boot leaves
 * the portal routing the *previous* bundle's hashed filenames: the new ones
 * match nothing, fall through to the deep-link handler, and every asset comes
 * back as index.html with `content-type: text/html`. What that looks like from
 * the outside is four unrelated failures — the asset content-type check, plus
 * three "#root never mounted", because the browser was handed HTML where it
 * asked for JavaScript. Production builds the image before it boots a
 * container; so does this now.
 *
 * The result is reported later, in the `spa` group where it reads in order.
 */
const spaBuild = { detail: null, error: null };

function buildSpa() {
  try {
    const r = spawnSync("pnpm", ["--filter", "@azx-pbc/portal-web", "build"], {
      cwd: ROOT,
      encoding: "utf8",
    });
    assert(r.status === 0, `build failed:\n${(r.stderr || r.stdout || "").slice(-1200)}`);
    const m = (r.stdout || "").match(/(\d+) modules transformed/);
    spaBuild.detail = m ? `${m[1]} modules` : "built";
  } catch (err) {
    spaBuild.error = err;
  }
}

/** Run the built CLI against THIS stack's portal. */
function helix(...args) {
  return spawnSync(process.execPath, [CLI_BIN, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...SVC_ENV, HELIX_PORTAL_URL: PORTAL, HELIX_TOKEN: TOKEN },
  });
}

/**
 * An isolated stack starts with an empty registry, so the edge and CLI groups
 * would find nothing live and silently SKIP — the coverage they used to get was
 * borrowed from whatever the developer happened to have deployed, which is not
 * something a test should depend on. Deploy one public and one internal app
 * through the real CLI path instead. Slugs are fixed, so a second run against
 * the same smoke database reuses them rather than accumulating rows.
 */
async function seedRegistry() {
  group("seed");
  console.log("\n\x1b[1mseed\x1b[0m — a live public + internal app for the edge to serve");

  const dir = join(OUT, "seed-app");
  mkdirSync(dir, { recursive: true });
  const plainHtml =
    "<!doctype html><html><head><title>helix smoke</title></head>" +
    "<body><h1>helix smoke fixture</h1></body></html>\n";
  const publicPixelOrigin = `https://smoke-public.${BASE_DOMAIN}:${STACK.ports.edge}`;
  const cspHtml =
    "<!doctype html><html><head><title>helix smoke csp</title></head><body>" +
    `<img id="remote" src="${publicPixelOrigin}/pixel.gif">` +
    '<img id="inline" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">' +
    "</body></html>\n";

  await check("cli bundle for seeding", () => buildCli());

  // smoke-csp redeploys every run so the served page always matches cspHtml;
  // the browser check depends on its exact images.
  for (const [slug, visibility, html, redeploy] of [
    ["smoke-public", "public", plainHtml, true],
    ["smoke-internal", "internal", plainHtml, false],
    ["smoke-csp", "public", cspHtml, true],
  ]) {
    await check(`live ${visibility} app (${slug})`, async () => {
      writeFileSync(join(dir, "index.html"), html);
      if (slug === "smoke-public") {
        copyFileSync(join(SMOKE_FIXTURES, "pixel.gif"), join(dir, "pixel.gif"));
      }
      // scope=all, not the default mine: the question is "does this slug exist
      // with a live version", not "is it mine". A principal-id re-base (e.g.
      // ADR-0048 changing the dev-token actor's oid) otherwise makes rows
      // seeded by an older build invisible here, and the create below fails
      // with slug_taken while the edge still serves the old app.
      const { body: apps } = await jget(`${PORTAL}/api/v1/apps?scope=all`, { headers: auth });
      const existing = Array.isArray(apps) ? apps.find((a) => a.slug === slug) : null;
      let how = "reused";
      if (!existing?.currentVersionId || redeploy) {
        if (!existing) {
          const c = helix("create", "--slug", slug, "--visibility", visibility);
          assert(c.status === 0, `create: ${(c.stderr || c.stdout || "").slice(-300)}`);
        }
        const d = helix("deploy", "--slug", slug, "--dir", dir, "--promote");
        assert(d.status === 0, `deploy: ${(d.stderr || d.stdout || "").slice(-400)}`);
        how = "deployed";
      }
      // The edge learns about it over LISTEN/NOTIFY, not on the request path;
      // wait for the projection so the edge group is not racing it.
      const deadline = Date.now() + 15_000;
      for (;;) {
        const { status } = await jget(EDGE(slug));
        if (status !== 404) return how;
        if (Date.now() > deadline) throw new Error("edge still 404s after 15s");
        await sleep(250);
      }
    });
  }
}

// ── the checks ────────────────────────────────────────────────────────────
const throwaway = `smoke-${randomUUID().slice(0, 8)}`;
let createdAppId = null;

async function checkPortal() {
  group("portal");
  console.log("\n\x1b[1mportal\x1b[0m — fastify + Prisma control plane");

  await check("public bootstrap config", async () => {
    const { status, body } = await jget(`${PORTAL}/api/v1/config`);
    eq(status, 200, "status");
    assert(typeof body.appPublicBase === "string", "appPublicBase missing");
    return body.appPublicBase;
  });

  await check("unauthenticated read is rejected", async () => {
    const { status } = await jget(`${PORTAL}/api/v1/apps`);
    eq(status, 401, "status");
  });

  await check("authenticated app list (Prisma read)", async () => {
    const { status, body } = await jget(`${PORTAL}/api/v1/apps`, { headers: auth });
    eq(status, 200, "status");
    assert(Array.isArray(body), "expected an array");
    assert(
      body.every((a) => typeof a.url === "string"),
      "every app must carry a control-plane-computed url",
    );
    return `${body.length} apps`;
  });

  await check("create app (Prisma write)", async () => {
    const { status, body } = await jget(`${PORTAL}/api/v1/apps`, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({
        slug: throwaway,
        displayName: "Smoke Test",
        visibility: { mode: "internal" },
      }),
    });
    eq(status, 201, "status");
    createdAppId = body.id;
    return body.slug;
  });

  await check("read back the created app", async () => {
    const { status, body } = await jget(`${PORTAL}/api/v1/apps/${throwaway}`, { headers: auth });
    eq(status, 200, "status");
    eq(body.slug, throwaway, "slug");
  });

  await check("zod boundary rejects a malformed body", async () => {
    const { status, body } = await jget(`${PORTAL}/api/v1/apps`, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({ slug: "BAD SLUG!!", visibility: { mode: "nonsense" } }),
    });
    eq(status, 400, "status");
    eq(body.error?.code, "validation_failed", "error code");
  });
}

async function checkEdge() {
  group("edge");
  console.log("\n\x1b[1medge\x1b[0m — data/policy plane (https, host routing, session gate)");

  const { body: apps } = await jget(`${PORTAL}/api/v1/apps`, { headers: auth });
  const live = Array.isArray(apps) ? apps.filter((a) => a.currentVersionId) : [];
  const pub = live.find((a) => a.visibility.mode === "public");
  const internal = live.find((a) => a.visibility.mode === "internal");

  await check("health reports registry-projection freshness", async () => {
    const { status, body } = await jget(`https://${BASE_DOMAIN}:${STACK.ports.edge}/health`);
    eq(status, 200, "status");
    const proj = body.checks?.find((c) => c.name === "registry-projection");
    assert(proj, "registry-projection check missing");
    return `${body.status} / projection ${proj.status}`;
  });

  if (!pub) {
    skip("public app is served from Blob", "no live public app in the registry");
    skip("CSP is injected", "no live public app in the registry");
  } else {
    await check("public app is served from Blob", async () => {
      const { status, headers } = await jget(EDGE(pub.slug));
      eq(status, 200, "status");
      assert(headers.get("content-type")?.includes("text/html"), "expected html");
      return pub.slug;
    });
    await check("CSP is injected", async () => {
      const { headers } = await jget(EDGE(pub.slug));
      const csp = headers.get("content-security-policy");
      const reportOnly = headers.get("content-security-policy-report-only");
      assert(csp, "no CSP header");
      const measurement = SVC_ENV.EDGE_IMG_SRC_REPORT_ONLY === "true";
      const allowAll = SVC_ENV.EDGE_IMG_SRC_ALLOW_ALL === "true";
      if (measurement) {
        assert(
          !reportOnly || csp.includes("img-src https:"),
          "measurement mode expected open enforced img-src",
        );
      } else if (allowAll) {
        assert(csp.includes("img-src https:"), "allow-all mode expected open img-src");
        assert(!reportOnly, "unexpected Report-Only CSP header");
      } else {
        assert(!reportOnly, "unexpected Report-Only CSP header");
        assert(csp.includes("img-src 'self' data: blob:"), "enforced img-src not tightened");
        assert(csp.includes("object-src 'none'"), "enforced missing object-src");
      }
      assert(csp.includes("frame-ancestors 'none'"), "frame-ancestors not locked down");
    });
  }

  if (!internal) {
    skip("session gate: 401 for API-style request", "no live internal app");
    skip("session gate: 302 to auth host for a navigation", "no live internal app");
  } else {
    await check("session gate: 401 for API-style request", async () => {
      const { status } = await jget(EDGE(internal.slug));
      eq(status, 401, "status");
    });
    await check("session gate: 302 to auth host for a navigation", async () => {
      // rawGet, not fetch — see the rawGet docblock for why.
      const r = await rawGet(EDGE(internal.slug), {
        Accept: "text/html,application/xhtml+xml",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
      });
      eq(r.status, 302, "status");
      const loc = r.headers.location ?? "";
      assert(loc.startsWith(`https://auth.${BASE_DOMAIN}`), `unexpected redirect target: ${loc}`);
      return new URL(loc).pathname;
    });
  }

  await check("unknown host is 404", async () => {
    const { status } = await jget(EDGE(`no-such-app-${randomUUID().slice(0, 6)}`));
    eq(status, 404, "status");
  });
}

async function checkSplitTls() {
  group("split-tls");
  console.log(
    "\n\x1b[1msplit-tls\x1b[0m — split cert, Node fetch, and Chromium on the apps domain",
  );
  if (!STACK.split) {
    skip("split-domain checks", "HELIX_APPS_DOMAIN is unset");
    return;
  }

  await check("split TLS cert and key exist", async () => {
    assert(existsSync(SPLIT_CERT) && existsSync(SPLIT_KEY), `run:\n  ${MKCERT_SPLIT_CMD}`);
    return "local-helix-split.pem";
  });

  const smokeHost = `smoke-x.${APPS_DOMAIN}`;
  const smokeUrl = `https://${smokeHost}:${STACK.ports.edge}/`;

  await check("TLS handshake authorizes apps-domain SNI", async () => {
    const sock = await new Promise((resolve, reject) => {
      const s = tls.connect(
        {
          host: "127.0.0.1",
          port: STACK.ports.edge,
          servername: smokeHost,
          rejectUnauthorized: true,
          lookup: loopbackLookup,
        },
        () => resolve(s),
      );
      s.on("error", reject);
    });
    const peer = sock.getPeerCertificate();
    sock.end();
    assert(sock.authorized, `TLS not authorized: ${sock.authorizationError}`);
    const san = peer.subjectaltname ?? "";
    assert(
      san.includes(`*.${APPS_DOMAIN}`) || san.includes(smokeHost),
      `peer SAN missing *.${APPS_DOMAIN}: ${san}`,
    );
    return san.split(", ").slice(0, 2).join(", ");
  });

  await check("fetch reaches the edge on the apps domain (404)", async () => {
    let mechanism = splitFetchMechanism;
    let r;
    try {
      r = await fetch(smokeUrl);
    } catch (e) {
      const code = e.code ?? e.cause?.code;
      if (code !== "ENOTFOUND") throw e;
      const orig = dns.lookup;
      dns.lookup = loopbackLookup;
      mechanism = "dns.lookup-patch";
      splitFetchMechanism = mechanism;
      r = await fetch(smokeUrl);
      dns.lookup = orig;
    }
    eq(r.status, 404, "status");
    return mechanism ?? "fetch";
  });

  if (NO_BROWSER) {
    skip("Chromium reaches the apps domain", "--no-browser");
  } else if (!findChrome()) {
    skip("Chromium reaches the apps domain", "no cached Chromium (set HELIX_SMOKE_CHROME)");
  } else {
    let browser;
    try {
      browser = await launchBrowser({
        port: STACK.cdpPort + 2,
        ignoreCertErrors: true,
        hostRules: [APPS_DOMAIN, CONTROL_DOMAIN],
      });
    } catch (e) {
      skip("Chromium reaches the apps domain", e.message);
      return;
    }
    try {
      await check("Chromium reaches the apps domain without cert errors", async () => {
        browser.reset();
        await browser.navigate(smokeUrl);
        assert(
          browser.failedRequests.length === 0,
          `failed requests: ${browser.failedRequests.slice(0, 3).join(" | ")}`,
        );
        const certErr = browser.errors.some((e) => /certificate|SSL|TLS/i.test(e));
        assert(!certErr, `certificate errors: ${browser.errors.slice(0, 3).join(" | ")}`);
        return smokeHost;
      });
    } finally {
      browser.close();
    }
  }
}

async function checkEgress() {
  group("egress");
  console.log("\n\x1b[1megress\x1b[0m — mechanism plane (attested instruction verification)");

  await check("health is liveness-only", async () => {
    const { status, body } = await jget(`${EGRESS}/health`);
    eq(status, 200, "status");
    eq(body.status, "ok", "status field");
    assert(body.checks === undefined, "egress should report liveness only");
  });

  await check("missing instruction headers → 400", async () => {
    const { status, body } = await jget(`${EGRESS}/proxy`, { method: "POST" });
    eq(status, 400, "status");
    eq(body.code, "bad_target", "code");
  });

  await check("forged instruction is refused before dialing the target", async () => {
    const { status, body } = await jget(`${EGRESS}/proxy`, {
      method: "POST",
      headers: {
        "x-helix-instruction": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.forged",
        // A link-local target: if verification ever regressed, SSRF controls
        // are the only thing left standing. It must never get that far.
        "x-helix-target": "http://169.254.169.254/latest/meta-data/",
        "x-helix-method": "GET",
      },
    });
    eq(status, 401, "status");
    eq(body.code, "forbidden", "code");
  });
}

async function checkIdp() {
  group("idp");
  console.log("\n\x1b[1mdev-idp\x1b[0m — oidc-provider authorization_code + PKCE");

  const IDP = `http://localhost:${STACK.ports.idp}`;
  const jar = new Map();
  const putCookies = (r) => {
    for (const c of r.headers.getSetCookie?.() ?? []) {
      const [kv] = c.split(";");
      const i = kv.indexOf("=");
      jar.set(kv.slice(0, i), kv.slice(i + 1));
    }
  };
  const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");

  /** Follow redirects by hand so cookies accumulate and we can stop at the callback. */
  async function hop(url, max = 10) {
    let cur = url;
    for (let i = 0; i < max; i++) {
      const r = await fetch(cur, {
        redirect: "manual",
        headers: { Accept: "text/html", ...(jar.size ? { Cookie: cookieHeader() } : {}) },
      });
      putCookies(r);
      const loc = r.headers.get("location");
      if (!loc) return { final: cur, res: r, text: await r.text() };
      cur = new URL(loc, cur).toString();
      if (cur.startsWith(`https://auth.${BASE_DOMAIN}`)) return { final: cur, res: r, text: "" };
    }
    throw new Error("too many redirects");
  }

  let discovery;
  await check("discovery document", async () => {
    const { status, body } = await jget(`${IDP}/.well-known/openid-configuration`);
    eq(status, 200, "status");
    discovery = body;
    assert(body.code_challenge_methods_supported?.includes("S256"), "S256 PKCE not advertised");
    return body.issuer;
  });

  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  // Must equal what dev-idp registered for the edge client — the stack sets
  // IDP_EDGE_REDIRECT_URIS, and this is its first (https) entry.
  const redirectUri = `https://auth.${BASE_DOMAIN}:${STACK.ports.edge}/callback`;
  let code = null;

  await check("authorize → interaction → code", async () => {
    const url =
      `${IDP}/auth?client_id=helix-edge&response_type=code` +
      `&scope=${encodeURIComponent("openid profile email groups")}` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&state=smoke&nonce=${randomUUID()}` +
      `&code_challenge=${challenge}&code_challenge_method=S256`;
    const first = await hop(url);
    assert(/pick a user/i.test(first.text), "interaction page did not render the user picker");
    const m = first.text.match(/\?user=([^"]+)"/);
    assert(m, "no fixture user link on the interaction page");
    const done = await hop(`${first.final}?user=${m[1]}`);
    const got = new URL(done.final).searchParams.get("code");
    assert(got, `no authorization code in ${done.final}`);
    code = got;
    return decodeURIComponent(m[1]);
  });

  await check("token exchange yields an ID token with inline groups", async () => {
    assert(code, "no code from the previous step");
    const secret = process.env.IDP_EDGE_CLIENT_SECRET || "edge-dev-secret";
    const r = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: {
        Authorization: "Basic " + Buffer.from(`helix-edge:${secret}`).toString("base64"),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }),
    });
    eq(r.status, 200, "status");
    const tok = await r.json();
    assert(tok.id_token, "no id_token");
    const claims = JSON.parse(Buffer.from(tok.id_token.split(".")[1], "base64url").toString());
    // The edge never calls userinfo — it reads groups straight off the ID
    // token (Entra-style, conformIdTokenClaims:false). Guard that shape.
    assert(Array.isArray(claims.groups), "groups claim missing from the ID token");
    assert(claims.email, "email claim missing from the ID token");
    return `${claims.email} [${claims.groups.join(", ")}]`;
  });
}

async function checkSpa() {
  group("spa");
  console.log("\n\x1b[1mportal SPA\x1b[0m — vite build, served by the portal");

  // Ran before the services came up — see buildSpa() for why that ordering is
  // load-bearing rather than incidental.
  await check("vite production build", () => {
    if (spaBuild.error) throw spaBuild.error;
    return spaBuild.detail;
  });

  let assets = [];
  await check("portal serves the built index.html", async () => {
    const r = await fetch(`${PORTAL}/`);
    eq(r.status, 200, "status");
    const html = await r.text();
    assert(/<div id="root">/.test(html), "no #root mount point");
    assets = [...html.matchAll(/\/assets\/[A-Za-z0-9_.-]+\.(?:js|css)/g)].map((m) => m[0]);
    assert(assets.length >= 2, "expected at least a js and a css asset");
    return `${assets.length} hashed assets`;
  });

  await check("hashed assets resolve with correct content types", async () => {
    for (const a of assets) {
      const r = await fetch(PORTAL + a);
      eq(r.status, 200, `status for ${a}`);
      const ct = r.headers.get("content-type") ?? "";
      const want = a.endsWith(".js") ? "javascript" : "css";
      assert(ct.includes(want), `${a} served as ${ct}`);
    }
    return assets.length + " ok";
  });

  await check("SPA deep link falls through to index (client routing)", async () => {
    const r = await fetch(`${PORTAL}/apps/does-not-matter`);
    eq(r.status, 200, "status");
    assert((await r.text()).includes('id="root"'), "deep link did not serve the SPA shell");
  });
}

async function checkBrowser() {
  group("browser");
  console.log("\n\x1b[1mbrowser\x1b[0m — real Chromium over CDP");

  if (NO_BROWSER) return skip("SPA renders in a real browser", "--no-browser");
  if (!findChrome()) {
    return skip("SPA renders in a real browser", "no cached Chromium (set HELIX_SMOKE_CHROME)");
  }

  let browser;
  let cspBrowser;
  try {
    browser = await launchBrowser({
      port: STACK.cdpPort,
      hostRules: STACK.split ? [APPS_DOMAIN, CONTROL_DOMAIN] : [],
    });
    try {
      cspBrowser = await launchBrowser({
        port: STACK.cdpPort + 1,
        ignoreCertErrors: true,
        hostRules: STACK.split ? [APPS_DOMAIN, CONTROL_DOMAIN] : [BASE_DOMAIN],
      });
    } catch (e) {
      browser.close();
      throw e;
    }
  } catch (e) {
    return skip("SPA renders in a real browser", e.message);
  }

  try {
    await check("signed-out shell renders without page errors", async () => {
      browser.reset();
      await browser.navigate(`${PORTAL}/`);
      const kids = await browser.evaluate("document.querySelector('#root')?.children.length ?? -1");
      assert(kids > 0, "#root never mounted (React did not render)");
      assert(browser.errors.length === 0, `page errors: ${browser.errors.slice(0, 3).join(" | ")}`);
      const shot = await browser.screenshot(join(OUT, "signed-out.png"));
      return shot;
    });

    // Seed the per-tab bearer token the SPA reads (apps/portal-web/src/auth/tokenStore.ts)
    // so the authenticated screens render without an interactive IdP login.
    await browser.evaluate(
      `sessionStorage.setItem('azx.portal.token', ${JSON.stringify(JSON.stringify({ token: TOKEN }))})`,
    );

    for (const [name, path] of [
      ["dashboard", "/"],
      ["apps-list", "/apps"],
    ]) {
      await check(`authenticated ${name} renders`, async () => {
        browser.reset();
        await browser.navigate(PORTAL + path);
        const kids = await browser.evaluate(
          "document.querySelector('#root')?.children.length ?? -1",
        );
        assert(kids > 0, "#root never mounted");
        const text = await browser.evaluate("document.body.innerText.replace(/\\s+/g,' ')");
        // The sidebar's workspace nav — "Apps" and "Usage" together, so this does
        // not pass on the word "Apps" appearing anywhere in a page body.
        assert(
          /Apps\s+Usage/i.test(text),
          `chrome did not render the app shell: ${text.slice(0, 120)}`,
        );
        assert(
          browser.errors.length === 0,
          `page errors: ${browser.errors.slice(0, 3).join(" | ")}`,
        );
        assert(
          browser.failedRequests.length === 0,
          `failed requests: ${browser.failedRequests.slice(0, 3).join(" | ")}`,
        );
        await browser.screenshot(join(OUT, `${name}.png`));
        return join(OUT, `${name}.png`);
      });
    }

    await check(
      "enforced CSP blocks remote image and records violation for smoke-csp",
      async () => {
        const remoteOrigin = `https://smoke-public.${BASE_DOMAIN}:${STACK.ports.edge}`;
        const seenBefore = Date.now();
        cspBrowser.reset();
        await cspBrowser.navigate(EDGE("smoke-csp"));
        const remote = await cspBrowser.evaluate(`(() => {
        const el = document.querySelector('#remote');
        return { complete: el?.complete ?? false, naturalWidth: el?.naturalWidth ?? -1 };
      })()`);
        assert(
          remote.complete === true,
          `remote image complete expected true, got ${remote.complete}`,
        );
        assert(
          remote.naturalWidth === 0,
          `remote image naturalWidth expected 0, got ${remote.naturalWidth}`,
        );
        const inlineW = await cspBrowser.evaluate(
          "document.querySelector('#inline')?.naturalWidth ?? 0",
        );
        assert(inlineW === 1, `inline data: image naturalWidth expected 1, got ${inlineW}`);
        await sleep(3000);
        const reportPostData = cspBrowser.cspReportPosts.at(-1) ?? null;
        assert(reportPostData, "no /_csp-report POST captured");
        let inner;
        try {
          inner = JSON.parse(reportPostData)["csp-report"] ?? {};
        } catch {
          throw new Error("could not parse report POST body");
        }
        assert(
          String(inner["blocked-uri"] ?? "").startsWith(remoteOrigin),
          `blocked-uri expected to start with ${remoteOrigin}, got ${inner["blocked-uri"]}`,
        );
        const dispositionNote =
          inner.disposition === undefined
            ? "disposition absent (unknown)"
            : `disposition=${JSON.stringify(inner.disposition)}`;
        assert(
          inner.disposition === "enforce",
          `expected disposition enforce, got ${inner.disposition}`,
        );

        const { body: violations } = await jget(`${PORTAL}/api/v1/csp/violations`, {
          headers: auth,
        });
        const hit = (violations.violations ?? []).find(
          (v) =>
            v.appSlug === "smoke-csp" &&
            v.directive?.includes("img-src") &&
            String(v.blockedUri ?? "").startsWith(remoteOrigin) &&
            new Date(v.lastSeen).getTime() >= seenBefore - 5000,
        );
        assert(hit, `no recent img-src violation for smoke-csp against ${remoteOrigin}`);
        return `${hit.count} report(s); ${dispositionNote}`;
      },
    );

    await check("granted origin appears in smoke-csp CSP", async () => {
      const grantOrigin = `https://smoke-public.${BASE_DOMAIN}:${STACK.ports.edge}`;
      const dbUrl = SVC_ENV.DATABASE_URL;
      assert(dbUrl, "DATABASE_URL required for grant check");
      const cap = JSON.stringify({ externalOrigins: [grantOrigin] });
      try {
        const grant = spawnSync(
          "psql",
          [dbUrl, "-qtc", `UPDATE apps SET capabilities='${cap}'::jsonb WHERE slug='smoke-csp';`],
          {
            encoding: "utf8",
          },
        );
        assert(grant.status === 0, `psql grant failed: ${grant.stderr}`);
        const deadline = Date.now() + 15_000;
        let csp;
        for (;;) {
          const { headers } = await jget(EDGE("smoke-csp"));
          csp = headers.get("content-security-policy") ?? "";
          if (csp.includes(grantOrigin)) break;
          if (Date.now() > deadline) throw new Error("CSP never picked up granted origin");
          await sleep(250);
        }
        assert(
          csp.includes("connect-src") && csp.includes(grantOrigin),
          "connect-src missing grant",
        );
        assert(csp.includes("img-src") && csp.includes(grantOrigin), "img-src missing grant");
        cspBrowser.reset();
        await cspBrowser.navigate(EDGE("smoke-csp"));
        const remoteW = await cspBrowser.evaluate(
          "document.querySelector('#remote')?.naturalWidth ?? 0",
        );
        assert(remoteW === 1, `granted remote image naturalWidth expected 1, got ${remoteW}`);
        return grantOrigin;
      } finally {
        const clear = spawnSync(
          "psql",
          [dbUrl, "-qtc", `UPDATE apps SET capabilities='{}'::jsonb WHERE slug='smoke-csp';`],
          { encoding: "utf8" },
        );
        assert(clear.status === 0, `psql clear grant failed: ${clear.stderr}`);
      }
    });
  } finally {
    browser.close();
    cspBrowser?.close();
  }
}

async function checkCli() {
  group("cli");
  console.log("\n\x1b[1mhelix CLI\x1b[0m — esbuild bundle driven against the live portal");

  await check("esbuild bundle", () => buildCli());

  await check("CLI reads versions from the live portal", async () => {
    const { body: apps } = await jget(`${PORTAL}/api/v1/apps`, { headers: auth });
    const target = apps.find((a) => a.currentVersionId);
    assert(target, "no live app to query");
    const r = helix("versions", "--slug", target.slug);
    assert(r.status === 0, `cli exited ${r.status}: ${(r.stderr || r.stdout || "").slice(-400)}`);
    assert(/\blive\b/.test(r.stdout), `no live version in output:\n${r.stdout}`);
    return `${target.slug}: ${r.stdout.trim().split("\n").length - 1} versions`;
  });
}

// ── cleanup of the throwaway registry row ─────────────────────────────────
function cleanupThrowaway() {
  if (!createdAppId) return;
  const url = SVC_ENV.DATABASE_URL;
  if (!url) return console.log(`\n\x1b[33m! left behind app ${throwaway} (no DATABASE_URL)\x1b[0m`);
  const r = spawnSync(
    "psql",
    [url, "-qtc", `DELETE FROM apps WHERE id='${createdAppId}' AND slug='${throwaway}';`],
    {
      encoding: "utf8",
    },
  );
  if (r.status !== 0) console.log(`\n\x1b[33m! could not remove ${throwaway}: ${r.stderr}\x1b[0m`);
}

// ── main ──────────────────────────────────────────────────────────────────
async function main() {
  if (!TOKEN) {
    console.error("PORTAL_DEV_TOKEN is not set — run inside the devcontainer.");
    process.exit(2);
  }
  if (only && !GROUPS.includes(only)) {
    console.error(`--only must be one of: ${GROUPS.join(", ")}`);
    process.exit(2);
  }
  if (only === "split-tls" && !STACK.split) {
    console.error("split-tls requires HELIX_APPS_DOMAIN to be set.");
    process.exit(2);
  }
  if (STACK.split && (!existsSync(SPLIT_CERT) || !existsSync(SPLIT_KEY))) {
    console.error(
      `\x1b[31msplit TLS cert missing — create it before booting:\x1b[0m\n  ${MKCERT_SPLIT_CMD}\n`,
    );
    process.exit(2);
  }

  console.log(`\x1b[1mHelix smoke test\x1b[0m   artifacts → ${OUT}`);
  console.log(
    STACK.offset === 0
      ? `\x1b[33m! offset 0 — sharing the dev stack's ports and database\x1b[0m\n`
      : `\x1b[2misolated stack: offset ${STACK.offset}, ports ${PORTS.join(" ")}, db ${STACK.database}\x1b[0m\n`,
  );

  // Own database, so the throwaway app row and the shared rate-limit/login
  // counters never land in the dev database. Idempotent; only the first run
  // pays for the migrate.
  if (STACK.offset !== 0) {
    try {
      const { name, created } = ensureDatabase(SVC_ENV.DATABASE_URL, { quiet: true });
      console.log(`  \x1b[2m${created ? "created" : "reusing"} database ${name}\x1b[0m`);
    } catch (err) {
      console.error(`\n\x1b[31mcould not prepare the smoke database: ${err.message}\x1b[0m`);
      process.exit(2);
    }
  }

  // Before the services, not after: @fastify/static resolves the dist once at
  // boot (see buildSpa()). Skipped for `--only` runs that never serve the SPA,
  // so a targeted edge run stays fast.
  if (wanted("spa") || wanted("browser")) {
    console.log("building the SPA…");
    buildSpa();
  }

  console.log("booting services…");
  freePorts();
  for (const svc of SERVICES) startService(svc);
  for (const svc of SERVICES) {
    await check(`${svc.name} healthy on :${svc.port}`, () => waitHealthy(svc));
  }

  if (results.some((r) => !r.ok && !r.skipped)) {
    console.error("\n\x1b[31mservices did not come up — aborting\x1b[0m");
  } else {
    try {
      if (wanted("edge") || wanted("cli")) await seedRegistry();
      if (wanted("idp")) await checkIdp();
      if (wanted("portal")) await checkPortal();
      if (wanted("edge")) await checkEdge();
      if (wanted("split-tls") && (STACK.split || only === "split-tls")) await checkSplitTls();
      if (wanted("egress")) await checkEgress();
      if (wanted("spa")) await checkSpa();
      if (wanted("browser")) await checkBrowser();
      if (wanted("cli")) await checkCli();
    } finally {
      cleanupThrowaway();
    }
  }

  // ── report ──────────────────────────────────────────────────────────────
  const passed = results.filter((r) => r.ok).length;
  const failed = results.filter((r) => !r.ok && !r.skipped);
  const skipped = results.filter((r) => r.skipped);
  console.log(`\n${"─".repeat(60)}`);
  console.log(`\x1b[1m${passed} passed\x1b[0m, ${failed.length} failed, ${skipped.length} skipped`);
  if (failed.length) {
    console.log("\n\x1b[31mfailures:\x1b[0m");
    for (const f of failed) console.log(`  ${f.group}/${f.name}\n    ${f.detail}`);
    console.log(`\nservice logs: ${OUT}/*.log`);
  }

  if (KEEP) {
    console.log(`\n\x1b[2mservices left running (--keep). Stop with:\x1b[0m`);
    console.log(`  node scripts/free-port.mjs ${PORTS.join(" ")}`);
  } else {
    stopAll();
  }
  process.exit(failed.length ? 1 : 0);
}

process.on("SIGINT", () => {
  stopAll();
  process.exit(130);
});

main().catch((e) => {
  console.error("\n\x1b[31mfatal:\x1b[0m", e);
  cleanupThrowaway();
  stopAll();
  process.exit(1);
});
