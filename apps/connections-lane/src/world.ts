import { execSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect as tcpConnect, type Socket } from "node:net";
import { createServer as createTlsServer, type Server as TlsServer } from "node:tls";
import type { AddressInfo } from "node:net";
import { Pool } from "pg";
import type { FastifyInstance } from "fastify";
import { CONNECTIONS_CALLBACK_PATH, ConnectionMaterialSchema } from "@azx-pbc/shared";
import type { SecretStore } from "@azx-pbc/secret-store";
import { createSecretStore } from "@azx-pbc/secret-store";
import {
  startDevOAuthVendor,
  type RunningDevOAuthVendor,
  type DevOAuthVendorOptions,
} from "@azx-pbc/dev-oauth-vendor";
import { startDevIdp, type RunningDevIdp, findFixtureUser } from "@azx-pbc/dev-idp";
import { buildApp as buildEgressApp } from "@azx-pbc/egress/app";
import { CredentialRetirementSweep } from "@azx-pbc/egress/retire";
import { LiveProviders } from "@azx-pbc/egress/providerListener";
import { buildTestApp, uniqueSlug, type TestApp } from "@azx-pbc/portal/test-harness";
import { createPrismaClient, type PrismaClient } from "@azx-pbc/portal/db-client";
import { deriveExchangeKey } from "@azx-pbc/portal/internal-jwt";
import { buildApp as buildEdgeApp } from "@azx-pbc/edge/app";
import {
  HttpEgressProvider,
  HttpPortalProvider,
  LiveRegistry,
  PgSessionStore,
  PgUsageStore,
  deriveInstructionKey,
  hashSessionToken,
  newSessionId,
} from "@azx-pbc/edge/test/support";
import { FakeBlobReader, FakeOidcClient } from "@azx-pbc/edge/test/fakes";
import { testAuthConfig, testEdgeConfig } from "@azx-pbc/edge/test/config";
import { appPageHtml } from "./appFixture.js";

/**
 * The lane's world: the real edge, portal,
 * egress and dev IdP composed the way production composes them — the
 * connectionsJourney.integration.test.ts shape — with every
 * browser-facing hop on real TLS, because this composition is driven by a REAL
 * CHROMIUM, not by `app.inject()`.
 *
 * Browser boundary: the edge terminates no TLS of its own here (its server.ts
 * would bind the mkcert files); the lane puts a TLS terminator — a raw socket
 * pump, the same one the integration test fronts the fixture vendor with —
 * between the browser and the edge's plain-HTTP listener. Chromium maps the
 * dev base domain to 127.0.0.1 through `--host-resolver-rules` (no /etc/hosts
 * edit, so the lane is self-sufficient in CI), and runs headed under Xvfb with
 * Playwright's `--disable-popup-blocking` default REMOVED: the real popup
 * blocker must be in the engine for the blocked-open journey to
 * be engine evidence rather than a stub — under CDP automation defaults the
 * blocker never fires (measured; see the README).
 *
 * Arrange vs act: apps, providers, bindings, approvals and the app-user
 * session are arranged — through the portal's real API and the real session
 * store, the same arrange surface the integration test uses; every step of
 * the consent journey itself is the browser's act. The lane never inserts a
 * connection.
 *
 * Identity continuity: the app user IS a dev-IdP fixture user (alice). The
 * edge session is arranged with her `oid`, and the portal SPA's real OIDC
 * login (the My Connections leg) resolves to the same `oid` through the
 * portal's env-built verifier chain — so the connection the app journey
 * created is the connection My Connections shows, with no row supplied by the
 * lane.
 */

const BASE = "local.helix.azxlabs.io";
const APPS = process.env.HELIX_APPS_DOMAIN?.trim().toLowerCase() || BASE;
const AUTH_HOST = `auth.${BASE}`;
/** The app user: a dev-IdP fixture identity, so the portal login and the edge
 * session agree on one `oid` (the cross-plane principal, ADR-0048). */
const USER = findFixtureUser("alice@azx.dev")!;

const OWNER_URL = process.env.TEST_DATABASE_URL ?? "postgresql://helix:helix@db:5432/helix_test";
const LANE_DB = "helix_lane_test";
const LANE_URL = OWNER_URL.replace(/\/[^/]+$/, `/${LANE_DB}`);

function roleUrl(role: string): string {
  const u = new URL(LANE_URL);
  u.username = role;
  u.password = role;
  return u.toString();
}

/** Dev-only well-known values (the devcontainer's), defaulted so the lane runs
 * with zero env setup; CI sets the same values explicitly. */
function internalSecret(): Buffer {
  return Buffer.from(
    process.env.HELIX_INTERNAL_SECRET ?? "aGVsaXgtZGV2LWludGVybmFsLXNlY3JldC0zMmItbWluIQ==",
    "utf8",
  );
}
function exchangeSecret(): Buffer {
  return Buffer.from(
    process.env.HELIX_EXCHANGE_SECRET ?? "aGVsaXgtZGV2LWV4Y2hhbmdlLXNlY3JldC0zMmItbWluIQ==",
    "utf8",
  );
}

export interface LaneFixture {
  slug: string;
  appId: string;
  ref: string;
  providerId: string;
  vendor: RunningDevOAuthVendor;
  /** The https origin the vendor's authorize screen is reached on. */
  vendorAuthorizeOrigin: string;
  /** The lane-owned front in front of that vendor (the test knobs). */
  front: VendorFront;
  callbackUrl: string;
  sessionCookie: string;
  appOrigin: string;
}

/**
 * The lane-owned TLS front for one fixture vendor — the popup's authorize hop
 * terminates here, so the front is the deterministic hold point for the
 * journeys that must freeze the popup mid-travel (timeout backdating,
 * cancellation, forged notifications) and the arming window for the CDP gate
 * on the popup's later hops (whose requests are redirect continuations
 * Playwright's route layer never sees).
 *
 * How the hold works, given that a popup's "popup" event only fires once a
 * navigation COMMITS (a chain of 302s never does): the held /authorize gets an
 * interstitial document from the front — the popup commits, the test can grab
 * the page object — whose only script refetches `/authorize-go`, and THAT
 * fetch's response is what the front withholds until `releaseHold()`. The
 * browser then navigates to the captured real authorize target and the front
 * pumps it verbatim. No production code is involved in any of it; the vendor
 * sees two authorize requests (the first's code is never redeemed).
 *
 * The forged-page response exists only for the forged-vendor journey, whose
 * whole subject is a vendor page posting a forged message.
 */
export class VendorFront {
  origin: string;
  #holdArmed = false;
  #released = false;
  #held = false;
  #heldWaiters: Array<() => void> = [];
  #release: (() => void) | null = null;
  #respondOnce: ((requestTarget: string) => string) | null = null;

  constructor(origin: string) {
    this.origin = origin;
  }

  /** Hold the NEXT /authorize at the interstitial (the consult has committed
   * by the time the request arrives). */
  armHold(): void {
    this.#holdArmed = true;
    this.#released = false;
  }

  /** Resolves when the authorize request is actually held (deterministic;
   * late registration is safe — the state outlives the moment). */
  heldRequest(): Promise<void> {
    if (this.#held) return Promise.resolve();
    return new Promise((resolve) => {
      this.#heldWaiters.push(resolve);
    });
  }

  /** Release: the interstitial's continuation fetch answers, the popup
   * navigates on to the real authorize, and the journey resumes. */
  releaseHold(): void {
    this.#holdArmed = false;
    this.#released = true;
    this.#release?.();
    this.#release = null;
  }

  /** Serve the NEXT /authorize from the front itself (the forged-page
   * journey); the request target is passed so the page can link back to the
   * real flow. Resolves when the response has been written. */
  respondNextAuthorize(render: (requestTarget: string) => string): Promise<void> {
    return new Promise((resolve) => {
      this.#respondOnce = (target) => {
        resolve();
        return render(target);
      };
    });
  }

  /** The pump's intervention point for a connection's FIRST request chunk. */
  intercept(firstChunk: string, client: Socket, pump: (chunk: Buffer) => void): void {
    const target = firstChunk.slice(4, firstChunk.indexOf(" HTTP"));
    if (this.#respondOnce !== null && target.startsWith("/authorize")) {
      const render = this.#respondOnce;
      this.#respondOnce = null;
      this.#respondHtml(client, render(target), "keep-alive");
      return;
    }
    if (this.#holdArmed && target.startsWith("/authorize")) {
      this.#holdArmed = false;
      this.#held = true;
      for (const w of this.#heldWaiters) w();
      this.#heldWaiters.length = 0;
      // The interstitial: the popup's first COMMITABLE document. Its script's
      // fetch of /authorize-go is what the front withholds until release.
      this.#respondHtml(
        client,
        `<!doctype html><html><body><p>Continuing…</p><script>
fetch("/authorize-go", { cache: "no-store" }).then(function () {
  location.replace(${JSON.stringify(target)});
});
</script></body></html>`,
        "close",
      );
      return;
    }
    if (target.startsWith("/authorize-go")) {
      // The continuation fetch: held (no bytes) until release, then a bare
      // 204. A release that landed before the fetch arrived answers at once.
      if (this.#released) {
        client.write("HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n");
        return;
      }
      this.#release = () => {
        client.write("HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n");
      };
      return;
    }
    pump(Buffer.from(firstChunk, "utf8"));
  }

  #respondHtml(client: Socket, html: string, connection: string): void {
    client.write(
      "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncache-control: no-store\r\ncontent-length: " +
        Buffer.byteLength(html) +
        `\r\nconnection: ${connection}\r\n\r\n` +
        html,
    );
  }
}

export class LaneWorld {
  readonly baseDomain = BASE;
  readonly authHost = AUTH_HOST;
  readonly userOid = USER.oid;

  #certDir = mkdtempSync(join(tmpdir(), "lane-tls-"));
  #edgeTerminator: TlsServer | null = null;
  #edgeTerminatorSockets = new Set<Socket>();
  #edgeHttpPort = 0;
  #portalPort = 0;
  #idp: RunningDevIdp | null = null;
  #portal: TestApp | null = null;
  #edge: FastifyInstance | null = null;
  #registry: LiveRegistry | null = null;
  #sessionStore: PgSessionStore | null = null;
  #delegatedPool: Pool | null = null;
  #providers: LiveProviders | null = null;
  #sweep: CredentialRetirementSweep | null = null;
  #egress: FastifyInstance | null = null;
  #blob = new FakeBlobReader();
  #vendors: RunningDevOAuthVendor[] = [];
  #vendorClosers: Array<() => Promise<void>> = [];

  readonly instructionSecret = randomBytes(48);
  readonly instructionKey = deriveInstructionKey(randomBytes(48));

  // Custody: shared (the portal seals, egress opens) + delegated (egress only,
  // never the portal).
  readonly portalCustody: SecretStore = createSecretStore({ devMasterKey: randomBytes(32) });
  readonly delegatedCustody: SecretStore = createSecretStore({ devMasterKey: randomBytes(32) });

  /** The portal's own client — the lane's arrange + assertion surface. */
  prisma: PrismaClient | null = null;

  get edgeTlsPort(): number {
    if (!this.#edgeTerminator) throw new Error("lane world not started");
    return (this.#edgeTerminator.address() as AddressInfo).port;
  }

  get portalOrigin(): string {
    return `http://localhost:${this.#portalPort}`;
  }

  get idpIssuer(): string {
    if (!this.#idp) throw new Error("lane world not started");
    return this.#idp.issuer;
  }

  /** The callback URL every plane derives: the edge builds it with
   * `controlOrigin(config, "auth")`; the portal builds it from
   * `CONTROL_PUBLIC_BASE`. */
  get callbackUrl(): string {
    return `https://${AUTH_HOST}:${this.edgeTlsPort}${CONNECTIONS_CALLBACK_PATH}`;
  }

  appHost(slug: string): string {
    return `${slug}.${APPS}`;
  }

  appOrigin(slug: string): string {
    return `https://${this.appHost(slug)}:${this.edgeTlsPort}`;
  }

  /** A fresh fixture vendor per test — modes are per-INSTANCE state (the
   * fixture's own rule), so a test's deny/hang flip can never leak into the
   * next test. `apiTokenHeaderName` selects the named-header mode. Tracked for
   * the world's teardown. */
  async startVendor(opts: DevOAuthVendorOptions = {}): Promise<RunningDevOAuthVendor> {
    const vendor = await startDevOAuthVendor({
      clientId: "lane-fixture-client",
      clientSecret: "lane-fixture-client-secret-5f3a",
      redirectUris: [this.callbackUrl],
      ...opts,
    });
    this.#vendors.push(vendor);
    return vendor;
  }

  /** One TLS terminator in front of a vendor's authorize screen: the popup
   * navigates it over https (the entry points' redirect-hygiene bar) while the
   * vendor's own listener stays plain http — one pump per fixture, with
   * the VendorFront's hold/forged knobs at the boundary. */
  async frontVendorWithTls(vendor: RunningDevOAuthVendor): Promise<VendorFront> {
    const sockets = new Set<Socket>();
    const front = new VendorFront("");
    const server = createTlsServer(this.#tlsOptions(), (client) => {
      sockets.add(client);
      client.on("close", () => sockets.delete(client));
      // Byte-honest pump with one intervention point: the connection's FIRST
      // request chunk (every client connection to a front is fresh — the
      // authorize origin is new to the popup), where the front may hold or
      // answer an /authorize itself.
      let upstream: Socket | null = null;
      const pending: Buffer[] = [];
      const pump = (chunk: Buffer): void => {
        if (upstream) {
          upstream.write(chunk);
          return;
        }
        pending.push(chunk);
        if (pending.length === 1) {
          const u = tcpConnect(vendor.port, "127.0.0.1", () => {
            for (const b of pending) u.write(b);
            u.pipe(client);
          });
          u.on("error", () => client.destroy());
          upstream = u;
        }
      };
      client.on("data", (chunk: Buffer) => {
        if (upstream !== null || pending.length > 0) {
          pump(chunk);
          return;
        }
        front.intercept(chunk.toString("utf8"), client, (toPump) => pump(toPump));
      });
      client.on("error", () => upstream?.destroy());
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      // No host ⇒ dual-stack (::): the browser resolves `localhost` and may
      // dial either family first — a single-family bind made the held-authorize
      // race lose on runners whose resolver orders ::1 first.
      server.listen(0, () => resolve());
    });
    front.origin = `https://localhost:${(server.address() as AddressInfo).port}`;
    this.#vendorClosers.push(async () => {
      for (const s of sockets) s.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });
    return front;
  }

  #tlsOptions() {
    return {
      key: readFileSync(join(this.#certDir, "key.pem")),
      cert: readFileSync(join(this.#certDir, "cert.pem")),
    };
  }

  async start(): Promise<void> {
    // The My Connections leg drives the REAL portal SPA — build it (fast, and
    // always fresh: the portal serves apps/portal-web/dist by default).
    const repoRoot = join(import.meta.dirname, "../..");
    execSync("pnpm --filter @azx-pbc/portal-web build", { stdio: "pipe", cwd: repoRoot });

    // ── Scratch database, from the same migrations ──
    const adminUrl = OWNER_URL.replace(/\/[^/]+$/, "/helix");
    execSync(`psql "${adminUrl}" -c "DROP DATABASE IF EXISTS ${LANE_DB} WITH (FORCE)"`, {
      stdio: "pipe",
    });
    execSync(`psql "${adminUrl}" -c "CREATE DATABASE ${LANE_DB}"`, { stdio: "pipe" });
    execSync("pnpm --filter @azx-pbc/portal exec prisma migrate deploy", {
      stdio: "pipe",
      env: { ...process.env, DATABASE_URL: LANE_URL },
    });

    // The runtime roles are REQUIRED — an unprovisioned green run is not
    // evidence (the role-split suites' discipline).
    const missing: string[] = [];
    for (const role of ["helix_edge", "helix_egress", "helix_dev"]) {
      const probe = new Pool({ connectionString: roleUrl(role), max: 1 });
      try {
        await probe.query("SELECT 1");
      } catch {
        missing.push(role);
      } finally {
        await probe.end();
      }
    }
    if (missing.length > 0) {
      throw new Error(
        `runtime roles not provisioned (${missing.join(", ")}) — run ` +
          `.devcontainer/db-init/01-roles.sql; an unprovisioned lane run is not evidence`,
      );
    }

    // ── The one lane TLS cert: the edge's dev hosts + the vendor fronts ──
    const appsSan = APPS !== BASE ? `,DNS:*.${APPS},DNS:${APPS}` : "";
    execSync(
      `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 2 -nodes ` +
        `-subj "/CN=local.helix.azxlabs.io" ` +
        `-addext "subjectAltName=DNS:*.local.helix.azxlabs.io,DNS:local.helix.azxlabs.io,DNS:localhost${appsSan}"`,
      { cwd: this.#certDir, stdio: "pipe" },
    );

    // ── The edge's TLS terminator (binds first: everything else derives its
    // public topology from this port) ──
    const edgeTerminator = createTlsServer(this.#tlsOptions(), (client) => {
      this.#edgeTerminatorSockets.add(client);
      client.on("close", () => this.#edgeTerminatorSockets.delete(client));
      if (!this.#edge?.server) {
        client.destroy();
        return;
      }
      const upstream = tcpConnect(this.#edgeHttpPort, "127.0.0.1", () => {
        client.pipe(upstream);
        upstream.pipe(client);
      });
      upstream.on("error", () => client.destroy());
      client.on("error", () => upstream.destroy());
    });
    await new Promise<void>((resolve, reject) => {
      edgeTerminator.once("error", reject);
      // Dual-stack (no host): the browser's `localhost` may resolve ::1-first.
      edgeTerminator.listen(0, () => resolve());
    });
    this.#edgeTerminator = edgeTerminator;

    // ── The portal's port, reserved before the IdP is built with the SPA's
    // redirect URI (the IdP registration and the portal's public config
    // reference each other) ──
    const net = await import("node:net");
    const reserved = net.createServer();
    await new Promise<void>((resolve) => reserved.listen(0, "127.0.0.1", () => resolve()));
    this.#portalPort = (reserved.address() as AddressInfo).port;
    await new Promise<void>((resolve) => reserved.close(() => resolve()));

    // ── Dev IdP: the real OIDC issuer, registered with the SPA's redirect ──
    this.#idp = await startDevIdp({
      webRedirectUris: [`${this.portalOrigin}/auth/callback`],
    });

    // ── Topology + auth env, before the control plane boots. The portal's
    // env-built verifier chain is the REAL one: an OIDC verifier over the dev
    // IdP's JWKS (the browser's SPA token is really verified) + the dev-token
    // verifier for the lane's arrange calls. ──
    process.env.PORTAL_OIDC_ISSUER = this.#idp.issuer;
    process.env.PORTAL_OIDC_AUDIENCE ??= "urn:helix:portal";
    process.env.PORTAL_OIDC_ALLOW_INSECURE = "true";
    process.env.PORTAL_ADMIN_GROUP_ID ??= "platform-admin";
    process.env.PORTAL_DEV_TOKEN ??= "lane-arrange-token";
    // The SECOND arrange actor (a distinct fixed oid — the approvals gate's
    // separation of duty compares oids, and CI runs with self-approve off):
    // the arrange identity files, this one decides.
    process.env.PORTAL_DEV_ADMIN_TOKEN ??= "lane-admin-arrange-token";
    process.env.PORTAL_DEV_ACTOR_GROUPS ??= "platform-admin";
    process.env.PORTAL_SECRET ??= "lane-portal-secret-lane-portal-secret-32b";
    process.env.HELIX_INTERNAL_SECRET ??= internalSecret().toString("utf8");
    process.env.HELIX_EXCHANGE_SECRET ??= exchangeSecret().toString("utf8");
    process.env.APP_PUBLIC_BASE = `https://${APPS}:${this.edgeTlsPort}`;
    if (APPS !== BASE) {
      process.env.CONTROL_PUBLIC_BASE = `https://${BASE}:${this.edgeTlsPort}`;
    }
    process.env.EDGE_PUBLIC_PORT = String(this.edgeTlsPort);

    // ── Egress: the delegated wiring on the helix_egress role ──
    const delegatedPool = new Pool({ connectionString: roleUrl("helix_egress"), max: 6 });
    this.#delegatedPool = delegatedPool;
    const providers = new LiveProviders({
      databaseUrl: roleUrl("helix_egress"),
      reconcileIntervalMs: 5_000,
      log: { info: () => {}, warn: () => {}, error: () => {} },
    });
    await providers.start();
    this.#providers = providers;
    const egress = buildEgressApp({
      config: {
        port: 0,
        host: "127.0.0.1",
        databaseUrl: roleUrl("helix_egress"),
        statementTimeoutMs: 5_000,
        providersReconcileIntervalMs: 60_000,
        retireSweepIntervalMs: 60_000,
        instructionSecret: this.instructionSecret,
        exchangeSecret: exchangeSecret(),
        limits: { maxBodyBytes: 1024 * 1024, timeoutMs: 10_000, llmTimeoutMs: 60_000 },
        managedIdentityConnections: [],
        allowPrivate: true,
        extraBlockedCidrs: [],
        allowInsecureConnection: true,
      },
      resolver: null,
      instructionKey: this.instructionKey,
      burnStore: null,
      exchange: {
        exchangeKey: deriveExchangeKey(exchangeSecret()),
        providers,
        credentialStore: this.portalCustody,
        delegatedStore: this.delegatedCustody,
        allowPrivate: true,
        allowInsecureConnection: true,
        timeoutMs: 10_000,
      },
      delegated: {
        pool: delegatedPool,
        providers,
        credentialStore: this.portalCustody,
        delegatedStore: this.delegatedCustody,
        timeoutMs: 10_000,
        allowInsecureConnection: true,
      },
    });
    await egress.listen({ port: 0, host: "127.0.0.1" });
    this.#egress = egress;
    process.env.PORTAL_EGRESS_URL = `http://127.0.0.1:${(egress.server.address() as AddressInfo).port}`;

    const sweep = new CredentialRetirementSweep({
      pool: delegatedPool,
      delegatedStore: this.delegatedCustody,
      intervalMs: 50,
    });
    sweep.start();
    this.#sweep = sweep;

    // ── Portal: the real control plane on the scratch DB, serving the built
    // SPA (the My Connections leg drives the real page) ──
    const portal = buildTestApp({
      prisma: createPrismaClient(LANE_URL),
      secretStore: this.portalCustody,
      // Empty auth opts = the env-built verifier chain (the real OIDC verifier
      // + the dev-token arrange verifier), resolved from the env above.
      auth: {},
      spaDist: process.env.LANE_SPA_DIST ?? join(import.meta.dirname, "../../portal-web/dist"),
    });
    this.#portal = portal;
    this.prisma = portal.prisma;
    await portal.app.ready();
    await portal.app.listen({ port: this.#portalPort, host: "127.0.0.1" });

    // ── Edge: the real data plane, the browser boundary in front of it ──
    const registry = new LiveRegistry({
      databaseUrl: roleUrl("helix_edge"),
      reconcileIntervalMs: 60_000,
      log: { info: () => {}, warn: () => {}, error: () => {} },
    });
    await registry.start();
    this.#registry = registry;
    this.#sessionStore = new PgSessionStore(roleUrl("helix_edge"), { max: 4 });
    const edge = buildEdgeApp({
      config: testEdgeConfig({
        baseDomain: APPS,
        controlDomain: BASE,
        auth: testAuthConfig({ allowInsecureIdp: true }),
        allowUnauthenticated: false,
        publicPort: this.edgeTlsPort,
        fetch: {
          egressUrl: process.env.PORTAL_EGRESS_URL,
          instructionSecret: this.instructionSecret,
          timeoutMs: 10_000,
          maxBodyBytes: 1024 * 1024,
          maxAppInFlight: 0,
        },
        internalSecret: internalSecret(),
        portalUrl: `http://127.0.0.1:${this.#portalPort}`,
      }),
      registry,
      blob: this.#blob,
      sessions: this.#sessionStore,
      oidc: new FakeOidcClient(),
      usage: new PgUsageStore(roleUrl("helix_edge"), { max: 4 }),
      egress: new HttpEgressProvider(process.env.PORTAL_EGRESS_URL as string, {
        timeoutMs: 10_000,
      }),
      instructionKey: this.instructionKey,
      portal: new HttpPortalProvider(`http://127.0.0.1:${this.#portalPort}`),
    });
    await edge.ready();
    await edge.listen({ port: 0, host: "127.0.0.1" });
    this.#edgeHttpPort = (edge.server.address() as AddressInfo).port;
    this.#edge = edge;
  }

  async stop(): Promise<void> {
    await this.#sweep?.stop();
    await this.#providers?.stop();
    await this.#delegatedPool?.end();
    await this.#egress?.close();
    await this.#sessionStore?.close();
    await this.#edge?.close();
    await this.#portal?.close();
    for (const vendor of this.#vendors) await vendor.close();
    this.#vendors = [];
    for (const closer of this.#vendorClosers) await closer();
    this.#vendorClosers = [];
    // Drop keep-alive browser sockets, then the listener.
    for (const s of this.#edgeTerminatorSockets) s.destroy();
    await new Promise<void>((resolve) => this.#edgeTerminator?.close(() => resolve()));
    await this.#idp?.close();
    delete process.env.PORTAL_EGRESS_URL;
    delete process.env.APP_PUBLIC_BASE;
    delete process.env.CONTROL_PUBLIC_BASE;
    delete process.env.EDGE_PUBLIC_PORT;
    rmSync(this.#certDir, { recursive: true, force: true });
    try {
      execSync(
        `psql "${OWNER_URL.replace(/\/[^/]+$/, "/helix")}" -c "DROP DATABASE ${LANE_DB} WITH (FORCE)"`,
        { stdio: "pipe" },
      );
    } catch {
      // A dropped-later scratch database is not a lane failure.
    }
  }

  // ── Arrange (through real surfaces) ────────────────────────────────────────

  /** Owner-DSN query for arrange-time state and assertion polls. */
  async ownerQuery<T extends Record<string, unknown>>(
    sql: string,
    values: unknown[] = [],
  ): Promise<T[]> {
    const pool = new Pool({ connectionString: LANE_URL, max: 1 });
    try {
      return (await pool.query<T>(sql, values)).rows;
    } finally {
      await pool.end();
    }
  }

  /** The dev-token bearer header (the portal's arrange verifier). */
  arrangeAuth(): { authorization: string } {
    return { authorization: `Bearer ${process.env.PORTAL_DEV_TOKEN}` };
  }

  /** The admin arrange actor's bearer header — the identity that DECIDES
   * approval requests (a distinct dev-token actor, so CI's separation of
   * duty — self-approve unset — holds). */
  adminAuth(): { authorization: string } {
    return { authorization: `Bearer ${process.env.PORTAL_DEV_ADMIN_TOKEN}` };
  }

  async waitForRegistry(slug: string): Promise<void> {
    if (!this.#registry) throw new Error("lane world not started");
    const deadline = Date.now() + 10_000;
    while (this.#registry.getApp(slug) === undefined) {
      if (Date.now() > deadline) {
        throw new Error(`timed out waiting for the registry projection entry for ${slug}`);
      }
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  /**
   * Arrange one journey fixture through the portal's REAL API: the app (+ a
   * live version), the provider row (client credentials sealed by the portal's
   * own create path into the custody egress opens), the manifest binding WITH
   * the connect-helper grant, its approval, the app page in Blob — the real
   * edge serves it with the helper injected — and the app user's session.
   * Waits for the edge's live registry projection to pick the app up.
   */
  async seedFixture(
    tag: string,
    opts: {
      vendor: RunningDevOAuthVendor;
      scopes?: string[];
      tokenPlacement?: { kind: "header-bearer" } | { kind: "header"; name: string };
    },
  ): Promise<LaneFixture> {
    const ref = `lane-${tag}-${randomUUID().replace(/-/g, "").slice(0, 8)}`;
    const slug = uniqueSlug("lane");
    // Unique per fixture: My Connections renders the display name, and the
    // lane's later tests must be able to find THIS test's card by name.
    const displayName = `Lane Vendor ${ref}`;

    const created = await fetch(`${this.portalOrigin}/api/v1/apps`, {
      method: "POST",
      headers: { "content-type": "application/json", ...this.arrangeAuth() },
      body: JSON.stringify({
        slug,
        displayName: "Lane app",
        visibility: { mode: "internal" },
      }),
    });
    if (created.status !== 201) throw new Error(`app create failed: ${created.status}`);
    const appId = ((await created.json()) as { id: string }).id;

    // A live version row, so the projection entry looks deployed.
    await this.ownerQuery(
      `INSERT INTO versions (id, "appId", number, "blobPrefix", status, "createdAt")
       VALUES (gen_random_uuid(), $1::uuid, 1, $2, 'live', now())`,
      [appId, `apps/${appId}/1/`],
    );
    await this.ownerQuery(
      `UPDATE apps SET "currentVersionId" =
         (SELECT id FROM versions WHERE "appId" = $1::uuid) WHERE id = $1::uuid`,
      [appId],
    );

    const front = await this.frontVendorWithTls(opts.vendor);
    const made = await fetch(`${this.portalOrigin}/api/v1/providers`, {
      method: "POST",
      headers: { "content-type": "application/json", ...this.arrangeAuth() },
      body: JSON.stringify({
        ref,
        kind: "rest-delegated",
        displayName,
        // The authorize endpoint is the TLS-terminated front for the fixture's
        // authorize screen (https is the entry points' redirect-hygiene bar);
        // every egress-owned vendor call rides the fixture's http issuer.
        authorizeEndpoint: `${front.origin}/authorize`,
        tokenEndpoint: `${opts.vendor.issuer}/token`,
        requestedScopes: opts.scopes ?? ["read", "write"],
        apiOrigins: [opts.vendor.issuer],
        tokenPlacement: opts.tokenPlacement ?? { kind: "header-bearer" },
        env: "prod",
        clientId: "lane-fixture-client",
        clientSecret: "lane-fixture-client-secret-5f3a",
      }),
    });
    if (made.status !== 201) throw new Error(`provider create failed: ${made.status}`);
    const providerId = ((await made.json()) as { id: string }).id;

    // The manifest binding (fetch origin → provider) + the connect-helper
    // grant, and its approval — the provider-stamped filing the consult
    // re-checks, and the serving grant the helper's injection re-derives.
    const put = await fetch(`${this.portalOrigin}/api/v1/apps/${slug}/manifest`, {
      method: "PUT",
      headers: { "content-type": "application/json", ...this.arrangeAuth() },
      body: JSON.stringify({
        capabilities: {
          mcp: [],
          externalOrigins: [],
          fetch: {
            shim: false,
            origins: [{ origin: opts.vendor.issuer, provider: ref }],
          },
          shim: { connect: true },
        },
      }),
    });
    if (put.status !== 200) throw new Error(`manifest put failed: ${put.status}`);
    const pending = ((await put.json()) as { pending: string }).pending;
    const approved = await fetch(`${this.portalOrigin}/api/v1/approvals/${pending}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", ...this.adminAuth() },
      body: "{}",
    });
    if (approved.status !== 200) throw new Error(`approval failed: ${approved.status}`);

    // The app page in Blob — the real edge serves it with the connect helper
    // injected (the shim.connect grant is what makes that true).
    this.#blob.set(`apps/${appId}/1/index.html`, {
      body: appPageHtml({ ref, vendorIssuer: opts.vendor.issuer }),
      contentType: "text/html",
    });

    const sessionCookie = await this.seedSession(appId);

    // The specs consume two NOTIFY-driven projections, and both can lag the
    // fixture on a loaded runner (the 2-core CI box): the edge's registry
    // entry must carry the shim.connect grant (the served page injects the
    // connect helper from it — a page served before the grant NEVER gains it,
    // so the spec burns its whole timeout) and the bound fetch origin (the
    // delegated call's allowlist); egress's provider cache must hold the
    // seeded row (the exchange resolves against it). Wait for all three.
    // 15s, not the 10s poll default: the caches' reconcile intervals (60s
    // edge / 5s egress) must not be what a slow runner waits out.
    await this.pollUntil(
      async () => {
        const entry = this.#registry?.getApp(slug);
        return entry !== undefined &&
          entry.shim?.connect === true &&
          entry.fetch.connections.has(opts.vendor.issuer)
          ? true
          : null;
      },
      "the edge's registry projection carrying the shim grant + bound origin",
      15_000,
    );
    await this.pollUntil(
      async () => (this.#providers?.get(providerId)?.revision ?? null) !== null,
      "egress's provider cache catching up to the seeded provider",
      15_000,
    );
    return {
      slug,
      appId,
      ref,
      providerId,
      vendor: opts.vendor,
      vendorAuthorizeOrigin: front.origin,
      front,
      callbackUrl: this.callbackUrl,
      sessionCookie,
      appOrigin: this.appOrigin(slug),
    };
  }

  /** A real session row for the app user — the real store, on helix_edge. */
  async seedSession(appId: string): Promise<string> {
    if (!this.#sessionStore) throw new Error("lane world not started");
    const token = randomBytes(32).toString("base64url");
    await this.#sessionStore.createActive(
      {
        id: newSessionId(),
        appId,
        user: {
          oid: this.userOid,
          displayName: USER.name ?? USER.email,
          name: USER.name ?? USER.email,
          email: USER.email,
          kind: "user",
          groups: [],
        },
        refreshDueAt: new Date(Date.now() + 3_600_000),
        expiresAt: new Date(Date.now() + 8 * 3_600_000),
      },
      hashSessionToken(token),
    );
    return token;
  }

  /** Open a connection row's sealed material through the delegated custody. */
  async openMaterial(material: string): Promise<{ access: string; refresh: string }> {
    const envelope = ConnectionMaterialSchema.parse(JSON.parse(material));
    return {
      access: await this.delegatedCustody.open(envelope.access),
      refresh: await this.delegatedCustody.open(envelope.refresh),
    };
  }

  /** Poll observable state (no fixed sleeps). */
  async pollUntil<T>(attempt: () => Promise<T | null>, label: string, ms = 10_000): Promise<T> {
    const deadline = Date.now() + ms;
    for (;;) {
      const value = await attempt();
      if (value !== null) return value;
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }
}
