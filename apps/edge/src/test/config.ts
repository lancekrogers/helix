import type { AuthConfig, AzureBlobConfig, DevGatewayConfig, EdgeConfig } from "../config.js";

/** The well-known unit-test auth secret (32 bytes). Tests may derive keys
 *  from it to forge tokens — proving forgery still requires the key. */
export const TEST_AUTH_SECRET = Buffer.from("0123456789abcdef0123456789abcdef");

export function testAuthConfig(overrides: Partial<AuthConfig> = {}): AuthConfig {
  return {
    issuerUrl: "https://idp.example",
    clientId: "helix-edge",
    credential: { kind: "secret", clientSecret: "test-secret" },
    groupsClaim: "groups",
    principalClaim: "oid",
    scopes: "openid profile email groups",
    allowInsecureIdp: false,
    secret: TEST_AUTH_SECRET,
    sessionTtlMs: 8 * 60 * 60 * 1000,
    refreshAfterMs: 60 * 60 * 1000,
    handoffTtlSec: 30,
    clockToleranceSec: 5,
    ...overrides,
  };
}

/** Default SharedKey (dev/Azurite) blob config for unit tests. */
export function testBlobConfig(overrides: Partial<AzureBlobConfig> = {}): AzureBlobConfig {
  return {
    provider: "azure",
    endpoint: "http://azurite:10000/devstoreaccount1",
    container: "app-bundles",
    auth: {
      mode: "shared-key",
      accountName: "devstoreaccount1",
      accountKey: Buffer.from("dGVzdA==", "base64"),
    },
    ...overrides,
  };
}

/** Managed-identity blob config for unit tests exercising the bearer path. */
export function testManagedIdentityBlob(overrides: Partial<AzureBlobConfig> = {}): AzureBlobConfig {
  return {
    provider: "azure",
    endpoint: "https://prodacct.blob.core.windows.net",
    container: "app-bundles",
    auth: {
      mode: "managed-identity",
      clientId: "00000000-0000-0000-0000-000000000000",
      identityEndpoint: "http://169.254.169.254/msi/token",
      identityHeader: "test-identity-header",
    },
    ...overrides,
  };
}

/** Full EdgeConfig for unit tests (no real services behind it). */
export function testEdgeConfig(overrides: Partial<EdgeConfig> = {}): EdgeConfig {
  return {
    baseDomain: "local.helix.azxlabs.io",
    databaseUrl: "postgresql://unused",
    blob: testBlobConfig(),
    auth: null,
    allowUnauthenticated: true,
    // Both open surfaces opted in for the fixture so serving suites can exercise
    // them. NB the shipped default is now off (opt-in) — suites exercising the
    // disallow path override these to false.
    allowPublicApps: true,
    allowPasswordApps: true,
    publicScheme: "https",
    publicPort: 8080,
    tls: null,
    reconcileIntervalMs: 60_000,
    statementTimeoutMs: 10_000,
    llm: {
      endpoint: "https://api.anthropic.com",
      path: "/v1/messages",
      anthropicVersion: "2023-06-01",
      connection: "anthropic",
      openai: {
        endpoint: "https://api.openai.com",
        path: "/v1/chat/completions",
        connection: "openai",
      },
      defaultDollarsPerDay: 50,
      platformDollarsPerDay: 0,
    },
    // Off by default in unit tests; suites that exercise it pass a low `max`.
    anonRateLimit: { max: 0, windowMs: 60_000 },
    // Default: trust nothing (the socket peer is the client), as in prod until
    // EDGE_TRUST_PROXY names the ingress address.
    trustProxy: false,
    // Fetch-proxy off by default; suites that exercise it set egressUrl +
    // instructionSecret (and pass an egress provider into buildApp).
    fetch: {
      egressUrl: null,
      instructionSecret: null,
      timeoutMs: 30_000,
      maxBodyBytes: 10 * 1024 * 1024,
    },
    // Edge→portal mint key unset by default; the consult suites set it.
    internalSecret: null,
    // Auth-host /connections reverse proxy unset by default; the proxy suites
    // set it (and pass a portal provider into buildApp).
    portalUrl: null,
    ...overrides,
  };
}

/**
 * Dev-gateway config for the dev-gateway suites. Structurally lacks the
 * helix_edge DSN / blob (see {@link DevGatewayConfig}); buildDevGateway's deps
 * only need the shared {@link GatewayConfig} fields, which this shares with
 * {@link testEdgeConfig}.
 */
export function testDevGatewayConfig(overrides: Partial<DevGatewayConfig> = {}): DevGatewayConfig {
  return {
    baseDomain: "local.helix.azxlabs.io",
    tls: null,
    reconcileIntervalMs: 60_000,
    statementTimeoutMs: 10_000,
    trustProxy: false,
    // Same public topology the edge test config uses: the popup URL and the
    // consult's callback URL are built from these, never from the request.
    publicScheme: "https",
    publicPort: 8080,
    llm: {
      endpoint: "https://api.anthropic.com",
      path: "/v1/messages",
      anthropicVersion: "2023-06-01",
      connection: "anthropic",
      openai: {
        endpoint: "https://api.openai.com",
        path: "/v1/chat/completions",
        connection: "openai",
      },
      defaultDollarsPerDay: 50,
      platformDollarsPerDay: 0,
    },
    fetch: {
      egressUrl: null,
      instructionSecret: null,
      timeoutMs: 30_000,
      maxBodyBytes: 10 * 1024 * 1024,
    },
    internalSecret: null,
    portalUrl: null,
    devGateway: {
      databaseUrl: "postgresql://helix_dev:unused@db/helix",
      allowDevMode: true,
      port: 8082,
    },
    ...overrides,
  };
}
