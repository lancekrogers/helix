import { z } from "zod";

import { BASELINE_DOLLARS_PER_DAY } from "@azx-pbc/shared";
import { DEFAULT_STATEMENT_TIMEOUT_MS } from "./db/pool.js";
import { RESERVED_SUBDOMAINS } from "./routing/hosts.js";
import { isCspSafeHostname } from "./serving/csp.js";

/**
 * Edge configuration, resolved once at boot from the environment (project plan
 * §3: config selects implementations per environment). Everything the request
 * path needs is parsed and validated here so handlers never read process.env.
 */
/**
 * How the edge authenticates *itself* to Blob Storage. Two modes, and the
 * credential material lives inside the discriminant so it is *structurally*
 * impossible for the managed-identity path to carry an account key (issue #15):
 *
 * - `shared-key`: the hand-rolled SharedKey HMAC signer. Dev/Azurite only —
 *   Azurite has no AAD. Refused in production by {@link loadConfig}.
 * - `managed-identity`: an AAD bearer token fetched at runtime from the
 *   Container Apps identity endpoint (Storage Blob Data Reader). No standing
 *   credential on the most-exposed plane; the edge can only read.
 */
export type AzureBlobAuth =
  | {
      mode: "shared-key";
      accountName: string;
      /** Decoded shared key (the connection string carries it base64-encoded). */
      accountKey: Buffer;
    }
  | {
      mode: "managed-identity";
      /** User-assigned MI client_id (AZURE_CLIENT_ID) — disambiguates the token request. */
      clientId: string;
      /** Container Apps-injected token endpoint (IDENTITY_ENDPOINT). */
      identityEndpoint: string;
      /** Container Apps-injected shared header value (IDENTITY_HEADER). */
      identityHeader: string;
    };

export interface AzureBlobConfig {
  provider: "azure";
  /** Blob endpoint origin + account path, no trailing slash. */
  endpoint: string;
  container: string;
  auth: AzureBlobAuth;
}

/**
 * Discriminated union over blob storage providers. Azure-only in v0
 * (architecture §8 — providers stay behind internal seams): a new provider is
 * a new member here plus a {@link ../blob/client.js BlobReader} implementation
 * selected in `createBlobReader`; nothing downstream of the interface changes.
 */
export type BlobConfig = AzureBlobConfig;

/**
 * How the edge authenticates *itself* to the IdP's token endpoint (the
 * confidential code exchange). Entra offers two forms: a shared `secret`, or —
 * when a tenant policy blocks symmetric secrets — a `certificate`
 * (private_key_jwt). The portal/SPA/CLI are public clients and never need this.
 */
export type AuthClientCredential =
  | { kind: "secret"; clientSecret: string }
  | { kind: "certificate"; privateKeyPem: string; certificatePem: string };

/**
 * OIDC + session configuration for app-user auth (architecture §4.2,
 * Appendix A). Provider-generic on purpose: locally the issuer is
 * apps/dev-idp; the Entra swap is env-only.
 */
export interface AuthConfig {
  issuerUrl: string;
  clientId: string;
  /** Client authentication toward the IdP: shared secret or certificate. */
  credential: AuthClientCredential;
  /** ID-token claim carrying group ids (Entra and dev-idp: `groups`). */
  groupsClaim: string;
  /**
   * ID-token claim carrying the canonical principal id (ADR-0048, as
   * amended): Entra's `oid` by default. Configurable because claim names
   * vary by issuer — the same concession `EDGE_OIDC_GROUPS_CLAIM` already
   * makes — and on most non-Entra issuers the stable, client-independent id
   * IS their `sub` (pairwise `sub` is Entra's deviation from the OIDC norm,
   * not the norm). `sub` is the one name that would silently reintroduce the
   * pairwise bug against Entra, so it is refused at boot unless
   * `EDGE_OIDC_ALLOW_SUB_PRINCIPAL=true` — an explicit, greppable assertion
   * that this issuer's `sub` is stable. **Must equal the portal's
   * `PORTAL_OIDC_PRINCIPAL_CLAIM`**: the cross-plane correlation the ADR
   * pins assumes both planes read the same claim.
   */
  principalClaim: string;
  scopes: string;
  /** Permit a plain-http issuer — local dev-idp only. */
  allowInsecureIdp: boolean;
  /** ≥32 bytes; HKDF-derived into the handoff + flow-cookie keys. */
  secret: Buffer;
  /** Hard session cap (Appendix A.4: hours, not weeks). */
  sessionTtlMs: number;
  /** Silent re-auth (prompt=none) due after this much of the session. */
  refreshAfterMs: number;
  handoffTtlSec: number;
  clockToleranceSec: number;
}

/**
 * Config shared by the two processes that run the gateway machinery — the edge
 * and the dev-gateway. These are the only fields the reusable `/_api/*`
 * handlers, the registry projection, and CORS/TLS setup read. Everything a
 * *data plane* needs beyond this (a database role, blob custody, sessions) is
 * added by the per-process config that extends this base. Splitting it this way
 * is what lets {@link DevGatewayConfig} *structurally omit* `databaseUrl`/`blob`:
 * the dev-gateway process cannot even name the `helix_edge` pool or the blob
 * account, so the isolation thesis (dev-mode design §5.3) is a type property,
 * not a wiring convention.
 */
export interface GatewayConfig {
  /** Apps are served on `<slug>.<baseDomain>` (architecture §4.1). */
  baseDomain: string;
  /** Control hosts (`auth.`, `portal.`, `dev-api.`) live on this domain. Equal to `baseDomain` in the single-domain layout. */
  controlDomain: string;
  /**
   * Edge-terminated TLS (mkcert in dev). **Required outside production** — the
   * platform is HTTPS-only (`__Host-` cookies need Secure; app crypto APIs
   * like `crypto.randomUUID`/SubtleCrypto need a secure context). In
   * production this is null: ingress owns the cert and the process runs plain
   * HTTP behind it.
   */
  tls: { certFile: string; keyFile: string } | null;
  /** Full projection reload interval — the LISTEN/NOTIFY safety net. */
  reconcileIntervalMs: number;
  /**
   * Per-query `statement_timeout` (ms) applied to every Postgres pool so a
   * slow/stuck query can't pin a pooled connection and exhaust the pool — a DoS
   * the exposed plane must resist (ADR-0002). `0` disables.
   */
  statementTimeoutMs: number;
  /**
   * Fastify `trustProxy` — how `req.ip` is derived behind a proxy, and so the
   * rate-limit / login-throttle key. Default `false` (the socket peer). Behind
   * Container Apps' Envoy ingress that peer *is* the ingress, collapsing every
   * client into one bucket, so per-client limits need EDGE_TRUST_PROXY to name
   * the **address** of the trusted ingress — {@link parseTrustProxy} has the
   * accepted forms. On ACA that address is `100.64.0.0/10`: a workload-profile
   * environment draws ingress pod addresses from the platform-reserved RFC 6598
   * ranges (`100.100.x.x`), *not* from the apps subnet the container itself runs
   * in — measured 2026-09-03, after the apps-subnet default silently trusted
   * nothing for a full milestone (ADR-0011's 2026-09 amendment, issue #13).
   * `infra/azure` resolves that for the deployed platform; anything else in
   * front of the edge (CDN, WAF, second proxy) has its own answer and needs
   * re-verifying, since too broad a value makes X-Forwarded-For spoofable. The
   * dev-gateway is handed the same value (dev-mode design §5.4).
   */
  trustProxy: boolean | string;
  /**
   * LLM gateway vendor settings (architecture §6.1, M4). Always present with
   * defaults; whether the capability is *enabled* is gated separately by egress
   * being configured (`EDGE_EGRESS_URL` + `HELIX_INSTRUCTION_SECRET`) — the
   * vendor key is a `platform` secret egress resolves, never held by the edge
   * (ADR-0008). This block only names the vendor endpoint/version/connection.
   */
  llm: {
    /** Vendor origin (no path), e.g. `https://api.anthropic.com`. */
    endpoint: string;
    /**
     * Upstream request path (EDGE_LLM_ANTHROPIC_PATH), default `/v1/messages`.
     * Configurable because the endpoint is origin-only: a Foundry account serves
     * the Messages API under `/anthropic/v1/messages` (ADR-0046), which an
     * origin cannot express.
     */
    path: string;
    /** `anthropic-version` header value. */
    anthropicVersion: string;
    /**
     * Name of the `platform`-scoped secret holding the vendor key, resolved by
     * egress on the `llm` path. When set (with egress + instruction key), the LLM
     * call routes through egress and the edge never holds the key. The key value
     * lives in the secret store, never in edge config.
     */
    connection: string;
    /**
     * OpenAI-compatible upstream for the `gpt-*`/`o*` model families (M4.5+). An
     * **OpenAI-compatible base URL**: `https://api.openai.com` for OpenAI direct
     * today, a Foundry account (ADR-0046) or a Warden URL later — same code path.
     * Symmetric with Anthropic above: always named (defaults `connection`
     * `openai`, `endpoint` api.openai.com) and wired whenever egress is up.
     * Enabling it is just seeding that `platform` secret — no dedicated toggle.
     * Absent the secret, a `gpt-*` call 502s at egress, exactly as an unseeded
     * Anthropic key would.
     */
    openai: {
      /** OpenAI-compatible origin (no path), e.g. `https://api.openai.com`. */
      endpoint: string;
      /**
       * Upstream request path (EDGE_LLM_OPENAI_PATH), default
       * `/v1/chat/completions`. Foundry's v1 API serves it under
       * `/openai/v1/chat/completions`.
       */
      path: string;
      /** Name of the `platform`-scoped secret holding the OpenAI key. */
      connection: string;
    };
    /**
     * Daily LLM budget applied to an app whose manifest sets none
     * (`EDGE_LLM_DEFAULT_DOLLARS_PER_DAY`). Defaults to the approval baseline.
     * Not clamped to it: an operator who raises it enforces more than the
     * classifier showed the approver. `0` means an unset budget is unlimited.
     */
    defaultDollarsPerDay: number;
    /**
     * Platform-wide daily LLM spend ceiling in USD (`EDGE_LLM_PLATFORM_DOLLARS_PER_DAY`).
     * `0` or unset disables enforcement on this process. The dev gateway ignores it
     * (`helix_dev` has no `EXECUTE` on the aggregate function).
     */
    platformDollarsPerDay: number;
    /**
     * Max concurrent LLM calls per app across all edge replicas (`EDGE_LLM_MAX_APP_IN_FLIGHT`).
     * `0` disables.
     */
    maxAppInFlight: number;
    /**
     * Max concurrent LLM calls per authenticated user per app (`EDGE_LLM_MAX_USER_IN_FLIGHT`).
     * Anonymous callers are not bucketed by user. `0` disables.
     */
    maxUserInFlight: number;
    /**
     * Max concurrent LLM calls on this replica (`EDGE_LLM_MAX_IN_FLIGHT`). Per replica by
     * design; cross-replica limits use Postgres leases. `0` disables.
     */
    maxInFlight: number;
    /**
     * Wall-clock deadline for one upstream LLM call in ms (`EDGE_LLM_MAX_CALL_MS`). Also bounds
     * lease TTL (deadline plus a grace period). Must be positive — there is no off value.
     */
    maxCallMs: number;
  };
  /**
   * Fetch-proxy wiring (M4.5). The policy plane authorizes a `/_api/fetch` call
   * and hands a signed attested instruction to `helix-egress`. The capability is
   * enabled only when BOTH `egressUrl` and `instructionSecret` are present —
   * otherwise `/_api/fetch` 503s (fail-closed, like the LLM key).
   */
  fetch: {
    /** Internal URL of the egress service; null disables the capability. */
    egressUrl: string | null;
    /** Shared with helix-egress; HKDF-derived into the instruction signing key. */
    instructionSecret: Buffer | null;
    /** Timeout for the egress round-trip. */
    timeoutMs: number;
    /**
     * Per-direction body-size cap, enforced with a byte counter on the request
     * re-stream to egress and the response re-stream to the app (issue #8).
     * Mirrors egress's `EGRESS_MAX_BODY_BYTES` so both hops cap independently.
     */
    maxBodyBytes: number;
    /**
     * Max concurrent fetch-proxy calls per app across all edge replicas
     * (`EDGE_FETCH_MAX_APP_IN_FLIGHT`). `0` disables — no lease is taken. Lease TTL
     * is ten minutes; a call that outlives it stops counting (at most one residual
     * slot per such call).
     */
    maxAppInFlight: number;
  };
  /**
   * The edge↔portal internal-JWT key (HELIX_INTERNAL_SECRET):
   * the edge mints a per-call token (`apps/edge/src/internalJwt.ts`) that the
   * portal's internal routes verify. Mint side, so optional exactly like
   * `fetch.instructionSecret` — null leaves the edge→portal capability
   * unwired and the consuming routes refuse rather than degrade; it is never a
   * boot failure. The dev-gateway shares this parse (it consults the same
   * portal for the dev tier).
   */
  internalSecret: Buffer | null;
  /**
   * Internal base URL of helix-portal (EDGE_PORTAL_URL) —
   * the origin the auth host's `/connections/*` reverse proxy forwards to over
   * plain HTTP behind the ingress (on ACA one hostname binds one container app,
   * so the portal cannot be reached at the auth host directly). Null ⇒ the
   * proxy surface 503s fail-closed, exactly like an unconfigured egress URL;
   * it is never a boot failure. The consult/cancel seams
   * consume the same field, which is why it lives on the shared gateway config
   * beside {@link internalSecret} — the key those calls authorize with.
   */
  portalUrl: string | null;
  /**
   * Scheme for externally built URLs (redirect targets, cookie origins, the
   * dev journey's popup URL). The platform is **HTTPS-only** — always `https`.
   * Dev terminates TLS at the edge (mkcert); prod terminates at ingress and the
   * edge speaks plain HTTP behind it, but the *public* origin is https either
   * way.
   */
  publicScheme: "https";
  /** Public port for built URLs; scheme-default ports are omitted. */
  publicPort: number;
}

/**
 * Edge (data/policy plane) config: the gateway base plus everything the edge
 * uniquely needs — its least-privilege database role, blob custody, app-user
 * sessions, and the open-surface toggles. Resolved by {@link loadConfig}.
 */
export interface EdgeConfig extends GatewayConfig {
  /** helix_edge DSN — the registry projection + gateway stores connect on it. */
  databaseUrl: string;
  blob: BlobConfig;
  /**
   * Auth is fail-closed in two layers: with `auth: null` and the dev bypass
   * unset, app hosts serve nothing; the bypass itself is refused in
   * production builds.
   */
  auth: AuthConfig | null;
  /**
   * Dev-only bypass: serve app content without sessions. Pre-M3 meaning
   * ("serve at all") narrows to "skip the session gate" once auth lands.
   */
  allowUnauthenticated: boolean;
  /**
   * Whether this deployment permits `public` (anonymous, no-gate) apps. When
   * false, the edge refuses to serve a public app — assets 403, `/_api/*`
   * refuses the anonymous caller — even one already set that way; the owner
   * migrates it down to internal/group in the portal to restore service. The
   * flag polarity is "allow", defaulting off: a deployment must set
   * `EDGE_ALLOW_PUBLIC_APPS=true` to opt this surface in (the parse below is
   * `=== "true"`).
   */
  allowPublicApps: boolean;
  /**
   * Whether this deployment permits `password` (shared-passphrase) apps — the
   * other open surface. When false, the edge refuses to serve a password app
   * (assets 403, `/_api/*` and the `/_auth/login` challenge both dead). Same
   * "allow"/default-off polarity as {@link allowPublicApps}.
   */
  allowPasswordApps: boolean;
  /** Per-IP rate limit for the anonymous tier on `public` apps (app-data design §7). Caps every anonymous `/_api/*` gateway call, keyed per IP+app within a
   * fixed window — the anonymous writer/visitor has no per-user budget to
   * charge, so this is the only per-source cap on an open public surface.
   * Authenticated callers are never limited here (they answer to per-app
   * budgets). `max: 0` disables the limiter.
   */
  anonRateLimit: { max: number; windowMs: number };
  /**
   * Origins appended to every app's img-src (EDGE_IMG_SRC_EXTRA). Operator-trusted
   * image hosts, so owners need no per-app approval for them. Never connect-src.
   * Do not list a host that fetches attacker-chosen URLs: that is a sink.
   */
  imgSrcExtra: string[];
  /**
   * EDGE_IMG_SRC_REPORT_ONLY: the measurement window before the default takes
   * effect (the previous open `img-src` enforced, the tightened policy Report-Only).
   * Parsed with `=== "true"`.
   */
  imgSrcReportOnly: boolean;
  /**
   * EDGE_IMG_SRC_ALLOW_ALL: put `https:` back in every app's img-src. For
   * installs on the one-org model that accept the open image channel. Default
   * false (tight); object-src stays 'none' either way.
   */
  imgSrcAllowAll: boolean;
}

/**
 * Dev-gateway config (dev-mode design §3, §5.4): the gateway base plus the
 * `helix_dev` DSN it runs on. It deliberately has NO `databaseUrl`/`blob`/`auth`
 * — the dev-gateway never opens the `helix_edge` pool, reads a blob, or runs the
 * session path, and the type makes that *unrepresentable* rather than merely
 * unused. Resolved by {@link loadDevGatewayConfig}, which requires
 * `EDGE_DEV_DATABASE_URL` and refuses any owner-DSN fallback.
 */
export interface DevGatewayConfig extends GatewayConfig {
  devGateway: {
    /** helix_dev DSN — required (no fallback); the env-literal RLS holds only as helix_dev. */
    databaseUrl: string;
    /** Per-plane opt-in (EDGE_ALLOW_DEV_MODE); the dev-gateway refuses to serve unless true. */
    allowDevMode: boolean;
    /** Port the dev-gateway listens on (its own process). */
    port: number;
  };
}

const ConnectionStringSchema = z.object({
  accountName: z.string().min(1),
  accountKey: z.string().base64().min(1),
  blobEndpoint: z.url(),
});

/**
 * Parse an Azure storage connection string (`Key=Value;…`). Values may contain
 * `=` (the base64 account key does), so split each pair on the first `=` only.
 */
export function parseConnectionString(connectionString: string): {
  accountName: string;
  accountKey: Buffer;
  blobEndpoint: string;
} {
  const pairs = new Map<string, string>();
  for (const part of connectionString.split(";")) {
    if (!part) continue;
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    pairs.set(part.slice(0, eq).trim(), part.slice(eq + 1).trim());
  }

  const protocol = pairs.get("DefaultEndpointsProtocol") ?? "https";
  const suffix = pairs.get("EndpointSuffix") ?? "core.windows.net";
  const accountName = pairs.get("AccountName");
  const parsed = ConnectionStringSchema.parse({
    accountName,
    accountKey: pairs.get("AccountKey"),
    // An explicit BlobEndpoint (Azurite) wins; otherwise derive the Azure one.
    blobEndpoint: pairs.get("BlobEndpoint") ?? `${protocol}://${accountName ?? ""}.blob.${suffix}`,
  });

  return {
    accountName: parsed.accountName,
    accountKey: Buffer.from(parsed.accountKey, "base64"),
    blobEndpoint: parsed.blobEndpoint.replace(/\/+$/, ""),
  };
}

/**
 * Resolve the blob provider + auth from the environment (issue #15). Managed
 * identity is preferred; the SharedKey/account-key path is a dev/Azurite
 * fallback refused in production. See the {@link AzureBlobAuth} discriminant.
 */
export function loadBlobConfig(env: NodeJS.ProcessEnv): BlobConfig {
  const container = env.BLOB_CONTAINER ?? "app-bundles";
  const blobEndpoint = env.AZURE_STORAGE_BLOB_ENDPOINT;
  const clientId = env.AZURE_CLIENT_ID;
  const connectionString = env.AZURE_STORAGE_CONNECTION_STRING;
  const isProduction = env.NODE_ENV === "production";

  // Managed identity: present endpoint + client_id select it, and it wins over
  // any connection string so a stale account-key secret can't be a fallback.
  if (present(blobEndpoint) && present(clientId)) {
    const identityEndpoint = env.IDENTITY_ENDPOINT;
    const identityHeader = env.IDENTITY_HEADER;
    if (!present(identityEndpoint) || !present(identityHeader)) {
      throw new Error(
        "Managed-identity blob auth needs IDENTITY_ENDPOINT and IDENTITY_HEADER " +
          "(injected by Container Apps when the user-assigned identity is attached)",
      );
    }
    return {
      provider: "azure",
      endpoint: blobEndpoint.replace(/\/+$/, ""),
      container,
      auth: { mode: "managed-identity", clientId, identityEndpoint, identityHeader },
    };
  }

  // SharedKey (dev/Azurite): the full-RW account key must never be used in prod.
  if (present(connectionString)) {
    if (isProduction) {
      throw new Error(
        "SharedKey/account-key blob auth is refused in production; configure a " +
          "managed identity (AZURE_STORAGE_BLOB_ENDPOINT + AZURE_CLIENT_ID)",
      );
    }
    const {
      accountName,
      accountKey,
      blobEndpoint: endpoint,
    } = parseConnectionString(connectionString);
    return {
      provider: "azure",
      endpoint,
      container,
      auth: { mode: "shared-key", accountName, accountKey },
    };
  }

  throw new Error(
    "Blob auth requires AZURE_STORAGE_CONNECTION_STRING (dev/Azurite) or " +
      "AZURE_STORAGE_BLOB_ENDPOINT + AZURE_CLIENT_ID (managed identity)",
  );
}

const AuthEnvSchema = z.object({
  issuerUrl: z.url(),
  clientId: z.string().min(1),
  secret: z.base64().min(1),
});

const present = (v: string | undefined): v is string => v !== undefined && v !== "";

/**
 * Accept a PEM credential as raw PEM (`-----BEGIN…`) or, since env files dislike
 * multiline values, as base64-encoded PEM. Either way we hand PEM to the OIDC
 * client; a value that is neither is a config error.
 */
function decodePem(value: string, name: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith("-----BEGIN")) return trimmed;
  const decoded = Buffer.from(trimmed, "base64").toString("utf8");
  if (!decoded.includes("-----BEGIN")) {
    throw new Error(`${name} must be PEM or base64-encoded PEM`);
  }
  return decoded;
}

/**
 * Pick the IdP client credential from the env: a shared secret, or a
 * certificate pair (private_key_jwt — for tenants whose policy blocks symmetric
 * secrets). Exactly one form must be supplied.
 */
function loadClientCredential(env: NodeJS.ProcessEnv): AuthClientCredential {
  const clientSecret = present(env.EDGE_OIDC_CLIENT_SECRET)
    ? env.EDGE_OIDC_CLIENT_SECRET
    : undefined;
  const privateKey = present(env.EDGE_OIDC_CLIENT_PRIVATE_KEY)
    ? env.EDGE_OIDC_CLIENT_PRIVATE_KEY
    : undefined;
  const certificate = present(env.EDGE_OIDC_CLIENT_CERTIFICATE)
    ? env.EDGE_OIDC_CLIENT_CERTIFICATE
    : undefined;

  const hasSecret = clientSecret !== undefined;
  const hasCert = privateKey !== undefined || certificate !== undefined;
  if (hasSecret && hasCert) {
    throw new Error(
      "Set either EDGE_OIDC_CLIENT_SECRET or the certificate pair " +
        "(EDGE_OIDC_CLIENT_PRIVATE_KEY + EDGE_OIDC_CLIENT_CERTIFICATE), not both",
    );
  }
  if (hasSecret) return { kind: "secret", clientSecret };
  if (hasCert) {
    if (privateKey === undefined || certificate === undefined) {
      throw new Error(
        "Certificate auth needs both EDGE_OIDC_CLIENT_PRIVATE_KEY and EDGE_OIDC_CLIENT_CERTIFICATE",
      );
    }
    return {
      kind: "certificate",
      privateKeyPem: decodePem(privateKey, "EDGE_OIDC_CLIENT_PRIVATE_KEY"),
      certificatePem: decodePem(certificate, "EDGE_OIDC_CLIENT_CERTIFICATE"),
    };
  }
  throw new Error(
    "Auth config needs a client credential: set EDGE_OIDC_CLIENT_SECRET, or " +
      "EDGE_OIDC_CLIENT_PRIVATE_KEY + EDGE_OIDC_CLIENT_CERTIFICATE (certificate auth)",
  );
}

/**
 * The principal-claim name, with the one dangerous value gated (ADR-0048
 * decision 2, as amended): `sub` is stable on most issuers (Keycloak, Okta,
 * dex, Google) but pairwise per client on Entra — the exact bug the re-base
 * exists to kill — so choosing it must be an explicit act, not a typo. Any
 * other claim name is the operator's assertion that it is a stable,
 * client-independent id.
 */
function loadPrincipalClaim(env: NodeJS.ProcessEnv): string {
  const claim = env.EDGE_OIDC_PRINCIPAL_CLAIM ?? "oid";
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(claim)) {
    throw new Error(
      `EDGE_OIDC_PRINCIPAL_CLAIM must be 1-64 chars of [A-Za-z0-9_-] (got ${JSON.stringify(claim)})`,
    );
  }
  if (claim === "sub" && env.EDGE_OIDC_ALLOW_SUB_PRINCIPAL !== "true") {
    throw new Error(
      "EDGE_OIDC_PRINCIPAL_CLAIM=sub is refused by default: Entra's sub is pairwise per " +
        "client id — the exact bug ADR-0048 exists to kill. Set EDGE_OIDC_ALLOW_SUB_PRINCIPAL=" +
        "true only if this issuer's sub is stable across clients (Keycloak, Okta, dex, " +
        "Google — not Entra).",
    );
  }
  return claim;
}

/**
 * Parse the auth block. All-or-nothing: no auth env at all returns null (the
 * edge boots fail-closed and app hosts serve nothing without the dev bypass);
 * a partial block is a config error worth failing loudly on. The IdP client
 * credential is a shared secret or a certificate — see {@link loadClientCredential}.
 */
function loadAuthConfig(env: NodeJS.ProcessEnv): AuthConfig | null {
  const base = [env.EDGE_OIDC_ISSUER, env.EDGE_OIDC_CLIENT_ID, env.EDGE_AUTH_SECRET].filter(
    present,
  );
  const anyCredential =
    present(env.EDGE_OIDC_CLIENT_SECRET) ||
    present(env.EDGE_OIDC_CLIENT_PRIVATE_KEY) ||
    present(env.EDGE_OIDC_CLIENT_CERTIFICATE);
  if (base.length === 0 && !anyCredential) return null;
  if (base.length < 3) {
    throw new Error(
      "Partial auth config: EDGE_OIDC_ISSUER, EDGE_OIDC_CLIENT_ID and " +
        "EDGE_AUTH_SECRET must all be set together",
    );
  }

  const credential = loadClientCredential(env);
  const parsed = AuthEnvSchema.parse({
    issuerUrl: env.EDGE_OIDC_ISSUER,
    clientId: env.EDGE_OIDC_CLIENT_ID,
    secret: env.EDGE_AUTH_SECRET,
  });
  const secret = Buffer.from(parsed.secret, "base64");
  if (secret.length < 32) {
    throw new Error("EDGE_AUTH_SECRET must decode to at least 32 bytes");
  }
  const allowInsecureIdp = env.EDGE_OIDC_ALLOW_INSECURE === "true";
  if (new URL(parsed.issuerUrl).protocol !== "https:" && !allowInsecureIdp) {
    throw new Error("EDGE_OIDC_ISSUER must be https (or set EDGE_OIDC_ALLOW_INSECURE=true in dev)");
  }

  return {
    issuerUrl: parsed.issuerUrl.replace(/\/+$/, ""),
    clientId: parsed.clientId,
    credential,
    groupsClaim: env.EDGE_OIDC_GROUPS_CLAIM ?? "groups",
    principalClaim: loadPrincipalClaim(env),
    // The default is DEV-IDP SHAPED, deliberately: apps/dev-idp serves `groups` as a
    // real scope (see its ALL_SCOPES) and that is how group visibility is exercised
    // locally and in CI, neither of which sets this var. Entra has no `groups`
    // delegated permission — it emits group claims from the app registration — so an
    // Entra install MUST override this to "openid profile email". infra/azure hardcodes
    // that, so the mismatch only reaches a deployment that skips the template.
    scopes: env.EDGE_OIDC_SCOPES ?? "openid profile email groups",
    allowInsecureIdp,
    secret,
    sessionTtlMs: Number(env.EDGE_SESSION_TTL_MS ?? 8 * 60 * 60 * 1000),
    refreshAfterMs: Number(env.EDGE_SESSION_REFRESH_MS ?? 60 * 60 * 1000),
    handoffTtlSec: 30,
    clockToleranceSec: 5,
  };
}

/** proxy-addr's built-in range aliases, accepted verbatim alongside addresses. */
const TRUST_PROXY_PRESETS = new Set(["loopback", "linklocal", "uniquelocal"]);

/** One part of an EDGE_TRUST_PROXY list: an IP or a CIDR, v4 or v6. */
const TrustProxyAddress = z.union([z.cidrv4(), z.cidrv6(), z.ipv4(), z.ipv6()]);

/**
 * A CIDR part with a zero prefix ("0.0.0.0/0", "::/0", "10.0.2.0/0"): zod's
 * cidrv4/cidrv6 accept all three, and `Fastify()` then throws on them inside
 * proxy-addr ("invalid range on address") — a boot crash whose error says
 * nothing about what to write instead. Refusing them here is the same
 * boot-time failure with a message that does.
 */
const isZeroPrefixCidr = (part: string): boolean => {
  const slash = part.indexOf("/");
  if (slash === -1) return false;
  const suffix = part.slice(slash + 1);
  return /^\d+$/.test(suffix) && Number(suffix) === 0;
};

/**
 * A dotted-netmask CIDR ("10.0.2.0/255.255.254.0"). proxy-addr reads this form
 * exactly as written; the grammar here refuses it in favor of the prefix-length
 * spelling ("10.0.2.0/23"). Detected only to pick that error sentence — the
 * refusal itself is zod rejecting the part.
 */
const isDottedNetmaskCidr = (part: string): boolean =>
  /^\d+\.\d+\.\d+\.\d+\/\d+\.\d+\.\d+\.\d+$/.test(part);

/**
 * Parse EDGE_IMG_SRC_EXTRA: comma-separated https origins widened into every
 * app's `img-src` (enforced by default; Report-Only only during measurement).
 * Refuse boot on any part that is not a bare
 * origin — paths, queries, credentials, wildcards, and http: are all errors.
 */
export function parseImgSrcExtra(raw: string | undefined): string[] {
  const v = (raw ?? "").trim();
  if (!v) return [];
  const out: string[] = [];
  for (const part of v.split(",")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      throw new Error(
        `EDGE_IMG_SRC_EXTRA is not a list of https origins (bad: ${JSON.stringify(trimmed)}). ` +
          `Each comma-separated part must look like "https://images.example.com" or ` +
          `"https://images.example.com:8443": no path, query, credentials or wildcard.`,
      );
    }
    const normalized = trimmed.replace(/\/$/, "");
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.hostname.includes("*") ||
      !isCspSafeHostname(url.hostname) ||
      url.search !== "" ||
      url.hash !== "" ||
      url.pathname !== "/" ||
      normalized !== url.origin
    ) {
      throw new Error(
        `EDGE_IMG_SRC_EXTRA is not a list of https origins (bad: ${JSON.stringify(trimmed)}). ` +
          `Each comma-separated part must look like "https://images.example.com" or ` +
          `"https://images.example.com:8443": no path, query, credentials or wildcard.`,
      );
    }
    if (!out.includes(url.origin)) out.push(url.origin);
  }
  return out;
}

/**
 * Parse EDGE_TRUST_PROXY: unset/blank means false; true/false select booleans;
 * otherwise accept a comma-separated list of IPs, CIDRs, or proxy-addr presets.
 * Reject invalid values before Fastify starts. An incorrect trusted address
 * can collapse rate limits and collection audit hashes to the ingress IP.
 *
 * Validate more strictly than proxy-addr/ipaddr.js, which accepts legacy short
 * IPv4 forms: 10.0.2 can become 10.0.0.2 instead of the intended network.
 * Reject /0 (use the explicit boolean form), zone-suffixed IPv6, and dotted
 * netmasks (use prefix lengths). Reject hop counts removed by Fastify 5.12.1
 * (GHSA-3m5p-2c4r-xxw2); accept 0 only as false. `auto` belongs to the Azure
 * template and must be resolved before reaching this parser.
 */
function parseTrustProxy(raw: string | undefined): boolean | string {
  const v = (raw ?? "").trim();
  if (!v) return false;
  if (v === "true") return true;
  if (v === "false") return false;
  if (/^\d+$/.test(v)) {
    // `0` was never a trust decision: fastify branched on `if (trustProxy)`, so
    // it was falsy and behaved exactly like unset. Refusing it would turn a safe
    // no-op into a boot failure, and under Container Apps' 'Single' revision mode
    // a boot failure is a rollout that silently never takes.
    if (Number(v) === 0) return false;
    throw new Error(
      `EDGE_TRUST_PROXY no longer accepts a proxy hop count (got ${JSON.stringify(v)}). ` +
        `Name the trusted proxy's address instead: a CIDR/IP list such as the ACA ` +
        `ingress ("100.64.0.0/10"), or a proxy-addr preset such as "uniquelocal". ` +
        `In infra/azure this is the edgeTrustProxy param (HELIX_EDGE_TRUST_PROXY), which ` +
        `rejects a hop count at deploy time — unset it to trust the ACA ingress.`,
    );
  }
  if (v === "auto") {
    throw new Error(
      `EDGE_TRUST_PROXY does not accept "auto" — that is the infra/azure edgeTrustProxy ` +
        `sentinel, which main.bicep resolves to the ACA ingress range before it reaches ` +
        `the container. Pass the resolved CIDR, or leave EDGE_TRUST_PROXY unset to ` +
        `trust nothing (the socket peer is the client).`,
    );
  }
  // Fastify splits on "," and hands proxy-addr the list, so validate per part.
  const bad = v
    .split(",")
    .map((part) => part.trim())
    .filter(
      (part) =>
        (!TRUST_PROXY_PRESETS.has(part) && !TrustProxyAddress.safeParse(part).success) ||
        isZeroPrefixCidr(part),
    );
  if (bad.length > 0) {
    const advice: string[] = [];
    if (bad.some(isZeroPrefixCidr)) {
      advice.push(
        `A /0 range matches every address, which is "trust any peer" — the property the ` +
          `hop-count removal closed (GHSA-3m5p-2c4r-xxw2). Broad trust still has peer-validating ` +
          `spellings: a preset such as "uniquelocal", or a wide prefix such as "10.0.0.0/16".`,
      );
    }
    if (bad.some(isDottedNetmaskCidr)) {
      advice.push(
        `The dotted-netmask form is not accepted — spell the prefix length instead ` +
          `("10.0.2.0/255.255.254.0" is "10.0.2.0/23").`,
      );
    }
    throw new Error(
      `EDGE_TRUST_PROXY is not a trusted-proxy address list (bad: ${bad.map((b) => JSON.stringify(b)).join(", ")}). ` +
        `Every comma-separated part must be an IP ("10.0.2.4"), a CIDR with a nonzero prefix ` +
        `("10.0.2.0/23"), or a proxy-addr preset (${[...TRUST_PROXY_PRESETS].join("/")}). ` +
        `Watch for a dropped octet: "10.0.2" is not "10.0.2.0/23" — proxy-addr would read it as ` +
        `the single host 10.0.0.2, match nothing the ingress presents, and silently collapse ` +
        `req.ip to the ingress address.` +
        (advice.length > 0 ? ` ${advice.join(" ")}` : ""),
    );
  }
  return v;
}

/**
 * Parse a millisecond duration that must be a positive, finite number, throwing
 * rather than letting a typo through.
 *
 * A bare `Number()` here is not harmless: `Number("abc")` is `NaN`, and every
 * comparison against `NaN` is false, so a mistyped value silently disables
 * whatever the duration gates. For the reconcile interval specifically, `NaN`
 * reaches `setTimeout`, which coerces it to ~0 ms — a DB hot loop from every
 * replica, with `/health` reading green throughout because the loads keep
 * succeeding. Note `??` only catches `undefined`/`null`, so an empty-string env
 * var (`Number("") === 0`) needs the same guard.
 */
/** Largest timer value Node accepts without clamping to 1 ms (`setTimeout` / `AbortSignal.timeout`). */
export const MAX_POSITIVE_MS = 2_147_483_647;

function requirePositiveMs(
  raw: string | undefined,
  fallback: number,
  name: string,
  maxMs?: number,
): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(
      `${name} must be a positive number of milliseconds (got ${JSON.stringify(raw)})`,
    );
  }
  if (maxMs !== undefined && value > maxMs) {
    throw new Error(`${name} must be at most ${maxMs} milliseconds (got ${JSON.stringify(raw)})`);
  }
  return value;
}

function requireNonNegativeNumber(raw: string | undefined, fallback: number, name: string): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${name} must be a non-negative number (got ${JSON.stringify(raw)})`);
  }
  return value;
}

function requireNonNegativeInt(raw: string | undefined, fallback: number, name: string): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0 || !Number.isInteger(value)) {
    throw new Error(`${name} must be a non-negative integer (got ${JSON.stringify(raw)})`);
  }
  return value;
}

/**
 * Validate an LLM upstream path override. Egress binds
 * `target.pathname === instruction.path` (the path only), so anything URL
 * normalisation would rewrite — a query, a fragment, dot segments, a space —
 * can never equal the claim and would 403 every call, with the blame pointing
 * at egress policy rather than at this env var. Refuse it at boot instead, by
 * round-tripping through `new URL` rather than blacklisting characters.
 * Foundry needs no query: its v1 API is versionless (ADR-0046).
 */
function llmPath(value: string | undefined, fallback: string, envKey: string): string {
  const path = value ?? fallback;
  const parsed = new URL(path, "https://upstream.invalid");
  if (!path.startsWith("/") || parsed.search || parsed.hash || parsed.pathname !== path) {
    throw new Error(
      `${envKey} must be a bare path (leading /, no query or fragment, nothing URL-normalisable)`,
    );
  }
  return path;
}

const HOSTNAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

/** Resolve and validate the control domain pair against the apps base domain. */
export function resolveControlDomain(baseDomain: string, raw: string | undefined): string {
  const control = raw?.trim().toLowerCase();
  if (!control || control === baseDomain) return baseDomain; // today's layout
  for (const [name, value] of [
    ["EDGE_CONTROL_DOMAIN", control],
    ["EDGE_BASE_DOMAIN", baseDomain],
  ] as const) {
    if (!HOSTNAME.test(value)) {
      throw new Error(`${name} is not a valid hostname: ${value}`);
    }
  }
  if (control.endsWith(`.${baseDomain}`)) {
    throw new Error(
      `EDGE_CONTROL_DOMAIN (${control}) must not be a subdomain of EDGE_BASE_DOMAIN (${baseDomain}): ` +
        "an app could set a Domain= cookie that reaches the control hosts. Refusing to start.",
    );
  }
  for (const label of ["auth", "portal", "dev-api"] as const) {
    const onLabel = `${label}.${control}`;
    if (baseDomain === onLabel || baseDomain.endsWith(`.${onLabel}`)) {
      throw new Error(
        `EDGE_BASE_DOMAIN (${baseDomain}) must not be on or under ${onLabel} (EDGE_CONTROL_DOMAIN ${control}): ` +
          "an app could set a Domain= cookie that reaches the control hosts. Refusing to start.",
      );
    }
  }
  return control;
}

/**
 * Parse the config the gateway machinery shares across the edge and the
 * dev-gateway (see {@link GatewayConfig}). Neither the helix_edge DSN nor blob
 * custody appears here — those are edge-only and live in {@link loadConfig} — so
 * the dev-gateway loader can reuse this without being forced to supply env it
 * never uses. The HTTPS-only TLS rule applies to both processes (both terminate
 * TLS in dev, both run HTTP behind ingress in prod).
 */
function loadGatewayConfig(env: NodeJS.ProcessEnv): GatewayConfig {
  const certFile = env.EDGE_TLS_CERT_FILE;
  const keyFile = env.EDGE_TLS_KEY_FILE;
  if ((certFile && !keyFile) || (!certFile && keyFile)) {
    throw new Error("EDGE_TLS_CERT_FILE and EDGE_TLS_KEY_FILE must be set together");
  }
  const tls = certFile && keyFile ? { certFile, keyFile } : null;

  // HTTPS-only platform: outside production the process must terminate TLS
  // itself (mkcert). `__Host-` cookies require Secure, and hosted apps' crypto
  // APIs (`crypto.randomUUID`, SubtleCrypto) only exist in a secure context — so
  // a plain-HTTP dev process is never allowed. Production opts out only by being
  // production: ingress owns the cert and the process runs HTTP behind it.
  if (!tls && env.NODE_ENV !== "production") {
    throw new Error(
      "TLS is required for local dev (the platform is HTTPS-only): set " +
        "EDGE_TLS_CERT_FILE and EDGE_TLS_KEY_FILE. Re-run .devcontainer/post-create.sh " +
        "to generate the mkcert certs for *.local.helix.azxlabs.io.",
    );
  }

  const baseDomain = (env.EDGE_BASE_DOMAIN ?? "local.helix.azxlabs.io").toLowerCase();
  const controlDomain = resolveControlDomain(baseDomain, env.EDGE_CONTROL_DOMAIN);

  return {
    baseDomain,
    controlDomain,
    tls,
    reconcileIntervalMs: requirePositiveMs(
      env.EDGE_RECONCILE_INTERVAL_MS,
      60_000,
      "EDGE_RECONCILE_INTERVAL_MS",
    ),
    statementTimeoutMs: Number(env.EDGE_STATEMENT_TIMEOUT_MS ?? DEFAULT_STATEMENT_TIMEOUT_MS),
    trustProxy: parseTrustProxy(env.EDGE_TRUST_PROXY),
    llm: {
      endpoint: (env.EDGE_LLM_ENDPOINT ?? "https://api.anthropic.com").replace(/\/+$/, ""),
      path: llmPath(env.EDGE_LLM_ANTHROPIC_PATH, "/v1/messages", "EDGE_LLM_ANTHROPIC_PATH"),
      anthropicVersion: env.EDGE_LLM_ANTHROPIC_VERSION ?? "2023-06-01",
      connection: env.EDGE_LLM_ANTHROPIC_CONNECTION ?? "anthropic",
      openai: {
        endpoint: (env.EDGE_LLM_OPENAI_ENDPOINT ?? "https://api.openai.com").replace(/\/+$/, ""),
        path: llmPath(env.EDGE_LLM_OPENAI_PATH, "/v1/chat/completions", "EDGE_LLM_OPENAI_PATH"),
        connection: env.EDGE_LLM_OPENAI_CONNECTION ?? "openai",
      },
      defaultDollarsPerDay: requireNonNegativeNumber(
        env.EDGE_LLM_DEFAULT_DOLLARS_PER_DAY,
        BASELINE_DOLLARS_PER_DAY,
        "EDGE_LLM_DEFAULT_DOLLARS_PER_DAY",
      ),
      platformDollarsPerDay: requireNonNegativeNumber(
        env.EDGE_LLM_PLATFORM_DOLLARS_PER_DAY,
        0,
        "EDGE_LLM_PLATFORM_DOLLARS_PER_DAY",
      ),
      maxAppInFlight: requireNonNegativeInt(
        env.EDGE_LLM_MAX_APP_IN_FLIGHT,
        10,
        "EDGE_LLM_MAX_APP_IN_FLIGHT",
      ),
      maxUserInFlight: requireNonNegativeInt(
        env.EDGE_LLM_MAX_USER_IN_FLIGHT,
        3,
        "EDGE_LLM_MAX_USER_IN_FLIGHT",
      ),
      maxInFlight: requireNonNegativeInt(env.EDGE_LLM_MAX_IN_FLIGHT, 200, "EDGE_LLM_MAX_IN_FLIGHT"),
      maxCallMs: requirePositiveMs(
        env.EDGE_LLM_MAX_CALL_MS,
        600_000,
        "EDGE_LLM_MAX_CALL_MS",
        MAX_POSITIVE_MS,
      ),
    },
    fetch: {
      egressUrl: env.EDGE_EGRESS_URL || null,
      instructionSecret: loadInstructionSecret(env),
      // 120s, not 30s: egress holds its response headers until the vendor's
      // first byte, and a reasoning LLM (gpt-5-nano et al.) can easily think
      // longer than 30s before streaming anything — the edge's headersTimeout
      // was the failure that surfaced, not the vendor's own speed.
      timeoutMs: Number(env.EDGE_FETCH_TIMEOUT_MS ?? 120_000),
      maxBodyBytes: Number(env.EDGE_FETCH_MAX_BODY_BYTES ?? 10 * 1024 * 1024),
      maxAppInFlight: requireNonNegativeInt(
        env.EDGE_FETCH_MAX_APP_IN_FLIGHT,
        0,
        "EDGE_FETCH_MAX_APP_IN_FLIGHT",
      ),
    },
    internalSecret: loadInternalSecret(env),
    portalUrl: env.EDGE_PORTAL_URL || null,
    publicScheme: "https",
    publicPort: Number(env.EDGE_PUBLIC_PORT ?? env.EDGE_PORT ?? env.PORT ?? 8080),
  };
}

/** Load and validate the edge config from the environment; throws on gaps. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): EdgeConfig {
  // The edge connects as the least-privilege runtime role (app-data design
  // §2.1) — its grants are a tight union of the data-plane verbs, never the
  // owner. `EDGE_DATABASE_URL` (helix_edge) is required in production: the
  // `DATABASE_URL` fallback is the schema *owner*, which bypasses RLS even
  // under FORCE (a superuser/owner ignores row-level policies), silently
  // defeating the role split (ADR-0002). Outside production the owner-DSN
  // fallback stays as a convenience for setups without the role split, matching
  // the connection-string / dev-bypass prod-strict pattern elsewhere here.
  const databaseUrl = env.EDGE_DATABASE_URL ?? env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error(
      "EDGE_DATABASE_URL or DATABASE_URL is required (registry projection reads Postgres)",
    );
  }
  if (!env.EDGE_DATABASE_URL && env.NODE_ENV === "production") {
    throw new Error(
      "EDGE_DATABASE_URL (the least-privilege helix_edge role) is required in production; " +
        "refusing the DATABASE_URL fallback, which connects as the schema owner and bypasses " +
        "RLS, defeating the role split (ADR-0002).",
    );
  }
  // Azure is the only v0 provider. Two auth paths (issue #15):
  //   * managed-identity (prod): AZURE_STORAGE_BLOB_ENDPOINT + AZURE_CLIENT_ID,
  //     with the Container Apps-injected IDENTITY_ENDPOINT/IDENTITY_HEADER. The
  //     edge holds no standing Blob credential and can only read.
  //   * shared-key (dev/Azurite): AZURE_STORAGE_CONNECTION_STRING. Refused in
  //     production — the full-RW account key must never ride the exposed plane.
  // MI wins when both are set, so a prod image carrying a stale connection-string
  // secret can never silently fall back to the account key.
  const blob = loadBlobConfig(env);

  const allowUnauthenticated = env.EDGE_DEV_ALLOW_UNAUTHENTICATED === "true";
  if (allowUnauthenticated && env.NODE_ENV === "production") {
    throw new Error("EDGE_DEV_ALLOW_UNAUTHENTICATED is a dev bypass and is refused in production");
  }

  const imgSrcReportOnly = env.EDGE_IMG_SRC_REPORT_ONLY === "true";
  const imgSrcAllowAll = env.EDGE_IMG_SRC_ALLOW_ALL === "true";
  if (imgSrcReportOnly && imgSrcAllowAll) {
    throw new Error(
      "EDGE_IMG_SRC_REPORT_ONLY and EDGE_IMG_SRC_ALLOW_ALL cannot both be true: report-only is the " +
        "measurement window before enforcing the tightened img-src, while allow-all restores the open " +
        "channel — pick one posture per install.",
    );
  }

  return {
    ...loadGatewayConfig(env),
    databaseUrl,
    blob,
    auth: loadAuthConfig(env),
    allowUnauthenticated,
    // "Allow" polarity, default off: a mode is permitted only when explicitly
    // set to "true". This is the opt-in platform default (see the field docs on
    // EdgeConfig); a deployment opts a surface back in per environment.
    allowPublicApps: env.EDGE_ALLOW_PUBLIC_APPS === "true",
    allowPasswordApps: env.EDGE_ALLOW_PASSWORD_APPS === "true",
    anonRateLimit: {
      max: Number(env.EDGE_ANON_RATE_LIMIT ?? 60),
      windowMs: Number(env.EDGE_ANON_RATE_WINDOW_MS ?? 60_000),
    },
    imgSrcExtra: parseImgSrcExtra(env.EDGE_IMG_SRC_EXTRA),
    imgSrcReportOnly,
    imgSrcAllowAll,
  };
}

/**
 * Load and validate the dev-gateway config (dev-mode design §3, §5.4). Unlike
 * {@link loadConfig} it reads NO edge-only env: no `EDGE_DATABASE_URL`, no blob
 * config, no auth. The one DSN it needs — `EDGE_DEV_DATABASE_URL` (the helix_dev
 * role) — is **required, with no owner-DSN fallback**: the env-literal RLS that
 * pins the dev tier to `env='dev'` only holds when the process actually connects
 * as `helix_dev` (dev-mode §5.3), so an owner fallback would silently defeat the
 * whole isolation. The returned {@link DevGatewayConfig} structurally lacks the
 * helix_edge DSN and blob custody, so the process can't hold either.
 */
export function loadDevGatewayConfig(env: NodeJS.ProcessEnv = process.env): DevGatewayConfig {
  const databaseUrl = env.EDGE_DEV_DATABASE_URL;
  if (!databaseUrl) {
    throw new Error(
      "EDGE_DEV_DATABASE_URL (the least-privilege helix_dev role DSN) is required to run the " +
        "dev-gateway. There is deliberately no DATABASE_URL/owner fallback — the env-literal RLS " +
        "isolating the dev tier only holds when the process connects as helix_dev (dev-mode §5.3).",
    );
  }
  return {
    ...loadGatewayConfig(env),
    devGateway: {
      databaseUrl,
      allowDevMode: env.EDGE_ALLOW_DEV_MODE === "true",
      port: Number(env.EDGE_DEV_GATEWAY_PORT ?? 8082),
    },
  };
}

/** Parse the shared instruction secret; refuse a too-short one (would weaken the key). */
function loadInstructionSecret(env: NodeJS.ProcessEnv): Buffer | null {
  const raw = env.HELIX_INSTRUCTION_SECRET;
  if (!raw) return null;
  const buf = Buffer.from(raw);
  if (buf.byteLength < 32) {
    throw new Error("HELIX_INSTRUCTION_SECRET must be at least 32 bytes");
  }
  return buf;
}

/** Parse the shared edge↔portal internal-JWT key; refuse a too-short one (would weaken the key). */
function loadInternalSecret(env: NodeJS.ProcessEnv): Buffer | null {
  const raw = env.HELIX_INTERNAL_SECRET;
  if (!raw) return null;
  const buf = Buffer.from(raw);
  if (buf.byteLength < 32) {
    throw new Error("HELIX_INTERNAL_SECRET must be at least 32 bytes");
  }
  return buf;
}

/**
 * Builds app origins (`<slug>.<baseDomain>`). Control-plane labels (`auth`,
 * `portal`, …) must use {@link controlOrigin} — passing them here throws so an
 * unmigrated call site fails in tests instead of emitting `auth.<appsDomain>`.
 */
export function publicOrigin(config: GatewayConfig, hostLabelOrNull: string | null): string {
  if (hostLabelOrNull !== null && RESERVED_SUBDOMAINS.has(hostLabelOrNull)) {
    throw new Error(
      `publicOrigin() builds app origins; "${hostLabelOrNull}" is a control host, use controlOrigin()`,
    );
  }
  const host = hostLabelOrNull ? `${hostLabelOrNull}.${config.baseDomain}` : config.baseDomain;
  return originFor(config, host);
}

export type ControlLabel = "auth" | "portal" | "dev-api";

/** Origin for a control-plane host on {@link GatewayConfig.controlDomain}. */
export function controlOrigin(config: GatewayConfig, label: ControlLabel): string {
  return originFor(config, `${label}.${config.controlDomain}`);
}

function originFor(config: GatewayConfig, host: string): string {
  // HTTPS-only: omit the port only when it is the https default (443).
  const port = config.publicPort === 443 ? "" : `:${config.publicPort}`;
  return `${config.publicScheme}://${host}${port}`;
}
