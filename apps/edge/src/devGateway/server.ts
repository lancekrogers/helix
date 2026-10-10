import { readFileSync } from "node:fs";
import { llmEgressHopTimeoutMs } from "@azx-pbc/shared";
import { installGracefulShutdown } from "@azx-pbc/shared/lifecycle";
import { startTelemetry } from "@azx-pbc/telemetry";
import { buildDevGateway, SERVICE_NAME } from "./app.js";
import { loadDevGatewayConfig, type DevGatewayConfig } from "../config.js";
import { LiveRegistry, type RegistryLogger } from "../registry/listener.js";
import { EgressLlmProvider } from "../gateway/egressLlmProvider.js";
import { RoutingLlmProvider } from "../gateway/routingLlmProvider.js";
import { anthropicVendor, openAiVendor } from "../gateway/provider.js";
import { HttpEgressProvider, type EgressProvider } from "../gateway/egressProvider.js";
import { deriveInstructionKey } from "../gateway/instruction.js";
import { PgUsageStore } from "../gateway/usage.js";
import { PgAppDataStore } from "../gateway/data.js";
import type { LlmProvider } from "../gateway/provider.js";
import { HttpPortalProvider } from "../routing/portalProvider.js";
import { PgDevTokenStore } from "./devTokenStore.js";
import type { PoolClientErrorPhase } from "../db/pool.js";

/**
 * helix-dev-gateway entrypoint (dev-mode design §3, §11 step 3). A SEPARATE process
 * from the edge, running as the least-privilege `helix_dev` role — all stores +
 * the registry projection connect on `EDGE_DEV_DATABASE_URL`, so this process
 * physically cannot read a prod (`env='prod'`) row (the env-literal RLS pins
 * helix_dev to env='dev', §5.3). Refuses to start unless the surface is opted in.
 */

function loadDotEnvLocal(): void {
  let text: string;
  try {
    // devGateway/server.ts → apps/edge/.env.local
    text = readFileSync(new URL("../../.env.local", import.meta.url), "utf8");
  } catch {
    return;
  }
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

loadDotEnvLocal();

const host = process.env.HOST ?? "0.0.0.0";
// loadDevGatewayConfig reads ONLY the dev-gateway's own env (no edge DSN, no
// blob) and hard-requires EDGE_DEV_DATABASE_URL with no owner fallback — so the
// helix_dev DSN below is guaranteed, and this process can't hold a helix_edge
// pool (dev-mode §5.3). A config gap is a clean refuse-to-start, not a stack.
let config: DevGatewayConfig;
try {
  config = loadDevGatewayConfig();
} catch (err) {
  console.error(`helix-dev-gateway: refusing to start — ${(err as Error).message}`);
  process.exit(1);
}

// The explicit per-plane opt-in (dev-mode §10), kept separate from config
// validity so a not-enabled deployment reads clearly rather than as a gap.
if (!config.devGateway.allowDevMode) {
  console.error(
    "helix-dev-gateway: refusing to start — set EDGE_ALLOW_DEV_MODE=true to enable the dev surface.",
  );
  process.exit(1);
}
const devDatabaseUrl = config.devGateway.databaseUrl;

// Inert unless an OTLP endpoint is configured (ADR-0037). The fourth server
// entrypoint: the ADR's decision 3 says "only the three `server.ts` files", and
// this is the one it does not count. It is dev-only but it IS a deployed
// surface when `deployDevGateway` is on, and it already carried
// `traceContextMixin` and an `OTEL_EXPORTER_OTLP_ENDPOINT` in Bicep — both of
// which did nothing without this line.
//
// `inject-only` by default, like the edge: it terminates the same untrusted
// app traffic, on a cross-origin surface, so an inbound `traceparent` must
// never become a parent (decision 7).
const telemetry = startTelemetry(SERVICE_NAME);

let https: { cert: Buffer; key: Buffer } | null = null;
if (config.tls) {
  try {
    https = { cert: readFileSync(config.tls.certFile), key: readFileSync(config.tls.keyFile) };
  } catch (err) {
    throw new Error("EDGE_TLS_* points at unreadable files — re-run .devcontainer/post-create.sh", {
      cause: err,
    });
  }
}

const logRef: { current: RegistryLogger } = {
  current: { info: () => {}, warn: () => {}, error: () => {} },
};
/** One reporting sink for every pool — see the note in `../server.ts`. */
const onClientError = (err: unknown, ctx: { phase: PoolClientErrorPhase; label: string }): void => {
  logRef.current.warn(
    { event: "db.pool_client_error", pool: ctx.label, phase: ctx.phase, err },
    `pooled DB client dropped (${ctx.label}, ${ctx.phase})`,
  );
};
const registry = new LiveRegistry({
  databaseUrl: devDatabaseUrl,
  reconcileIntervalMs: config.reconcileIntervalMs,
  statementTimeoutMs: config.statementTimeoutMs,
  // helix_dev has a column-scoped grant that omits the password columns — the dev
  // tier never serves the password login and must not read a prod credential.
  includePasswords: false,
  log: {
    info: (obj, msg) => logRef.current.info(obj, msg),
    warn: (obj, msg) => logRef.current.warn(obj, msg),
    error: (obj, msg) => logRef.current.error(obj, msg),
  },
});

const usage = new PgUsageStore(devDatabaseUrl, {
  statementTimeoutMs: config.statementTimeoutMs,
  onClientError,
});
const appData = new PgAppDataStore(devDatabaseUrl, {
  statementTimeoutMs: config.statementTimeoutMs,
  onClientError,
});
const devTokens = new PgDevTokenStore(devDatabaseUrl, {
  statementTimeoutMs: config.statementTimeoutMs,
  onClientError,
});

// Fetch-proxy + LLM ride the same EgressProvider seam as the edge; env=dev is
// carried in the attested instruction (step 1). Fail-closed when unconfigured.
const llmHopTimeoutMs = llmEgressHopTimeoutMs(config.llm.maxCallMs);
const egress: EgressProvider | null = config.fetch.egressUrl
  ? new HttpEgressProvider(config.fetch.egressUrl, { timeoutMs: config.fetch.timeoutMs })
  : null;
const instructionKey = config.fetch.instructionSecret
  ? deriveInstructionKey(config.fetch.instructionSecret)
  : null;
const llmProvider: LlmProvider | null =
  egress && instructionKey
    ? new RoutingLlmProvider({
        anthropic: new EgressLlmProvider(
          anthropicVendor({
            endpoint: config.llm.endpoint,
            anthropicVersion: config.llm.anthropicVersion,
            connection: config.llm.connection,
            path: config.llm.path,
          }),
          egress,
          instructionKey,
          llmHopTimeoutMs,
        ),
        openai: new EgressLlmProvider(
          openAiVendor(config.llm.openai),
          egress,
          instructionKey,
          llmHopTimeoutMs,
        ),
      })
    : null;

// The dev tier's consent consult rides the same portal seam as the
// edge's reverse proxy — EDGE_PORTAL_URL + the internal mint key, both already
// on the shared gateway config. Unset ⇒ the consent route 503s fail-closed.
const portal = config.portalUrl ? new HttpPortalProvider(config.portalUrl) : null;

const app = buildDevGateway({
  config,
  registry,
  devTokens,
  appData,
  usage,
  llmProvider,
  egress,
  instructionKey,
  portal,
  https,
});
logRef.current = {
  info: (obj, msg) => app.log.info(obj, msg),
  warn: (obj, msg) => app.log.warn(obj, msg),
  error: (obj, msg) => app.log.error(obj, msg),
};
app.addHook("onClose", async () => {
  await registry.stop();
  await usage.close();
  await appData.close();
  await devTokens.close();
  await egress?.close();
  await llmProvider?.close();
  await portal?.close();
  // Last, after everything that could still record.
  await telemetry.shutdown();
});

// SIGTERM / SIGINT: drain in-flight requests and run the onClose hook above,
// bounded by a hard deadline. Mirrors `../server.ts` (default 10 s,
// SHUTDOWN_GRACE_MS overrides — a third of Container Apps' documented 30 s
// SIGTERM-to-SIGKILL window).
installGracefulShutdown(app, app.log);

try {
  await registry.start();
  await app.listen({ port: config.devGateway.port, host });
  app.log.info(
    {
      event: "boot.serving",
      service: SERVICE_NAME,
      port: config.devGateway.port,
      baseDomain: config.baseDomain,
      llmDefaultDollarsPerDay: config.llm.defaultDollarsPerDay,
      tls: https !== null,
      telemetry: telemetry.enabled,
    },
    `${SERVICE_NAME} serving`,
  );
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
