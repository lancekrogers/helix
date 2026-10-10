/**
 * helix-egress configuration, resolved once at boot (mirrors the edge's config
 * discipline — handlers never read process.env). The egress service is the
 * mechanism plane: it needs the DB (as `helix_egress`), the shared instruction
 * secret (to verify what the edge minted), a secret-store custody config, and
 * SSRF/limit knobs.
 */
import { DEFAULT_STATEMENT_TIMEOUT_MS } from "./pool.js";
import { parseCidrList, type ParsedCidr } from "./ssrf.js";
/**
 * One `EGRESS_MANAGED_IDENTITY_CONNECTIONS` entry. `connection` is the
 * operator-chosen platform connection name (kebab-case, like a secret name);
 * `hostSuffix` pins token injection to that vendor host (exact or subdomain),
 * so a forged instruction naming the connection but a foreign origin gets
 * nothing (ADR-0046). Pin the exact account host
 * (`foundry=contoso.services.ai.azure.com`), not the shared zone — a
 * `services.ai.azure.com`-wide rule authorises minting onto *every* Foundry
 * account, including one an attacker picks.
 */
export interface ManagedIdentityConnectionRule {
  connection: string;
  hostSuffix: string;
}

export interface EgressConfig {
  port: number;
  host: string;
  /** Connects as `helix_egress` (EGRESS_DATABASE_URL); falls back to DATABASE_URL in dev. */
  databaseUrl: string;
  /**
   * Per-query `statement_timeout` for both egress pools (`EGRESS_STATEMENT_TIMEOUT_MS`;
   * default {@link DEFAULT_STATEMENT_TIMEOUT_MS}). The same pool-exhaustion guard the
   * edge's pools carry (ADR-0002 ISSUE-05).
   */
  statementTimeoutMs: number;
  /**
   * How often the provider cache reconciles from current state regardless of
   * NOTIFY (`EGRESS_PROVIDERS_RECONCILE_INTERVAL_MS`; default 60s) — the
   * self-heal cadence that bounds how stale the cache can be after a missed
   * notification.
   */
  providersReconcileIntervalMs: number;
  /**
   * How often the credential-retirement sweep consumes the `pendingRetire`
   * ledger (`EGRESS_RETIRE_SWEEP_INTERVAL_MS`; default 60s) — well inside
   * the 15-minute recovery bound even with a failed pass retried
   * on top (ADR-0031 amendment item 12).
   */
  retireSweepIntervalMs: number;
  /** Shared with the edge; HKDF-derived into the instruction-verify key. >= 32 bytes. */
  instructionSecret: Buffer;
  /**
   * Shared with the portal; HKDF-derived into the exchange-JWT verify key
   * (HELIX_EXCHANGE_SECRET — `apps/egress/src/internalJwt.ts`).
   * Verify side, so required exactly like `instructionSecret`: the exchange
   * route has no degraded mode that still serves it. >= 32 bytes.
   */
  exchangeSecret: Buffer;
  /** Prod custody: Key Vault. */
  keyVaultUrl?: string;
  /**
   * Prod custody for DELEGATED token material: the dedicated, egress-only vault
   * (the `delegatedVaultName` topology). Read from
   * `AZURE_DELEGATED_KEY_VAULT_URL` — the same injection posture as
   * `AZURE_KEY_VAULT_URL` for the connections vault. Unset in prod leaves the
   * exchange operation unwired (it refuses fail-closed); the deployment
   * coupling (the vault must exist and egress must be its Officer before prod
   * use) is proven by the deployment, not by this config.
   */
  delegatedKeyVaultUrl?: string;
  /** Dev custody: path to the locally-generated KEK file (post-create.sh). */
  devKeyPath?: string;
  limits: { maxBodyBytes: number; timeoutMs: number };
  /**
   * Keyless LLM vendor auth (ADR-0046): connection names for which egress may
   * mint a **managed-identity** Entra token when no `platform` secret row exists,
   * each pinned to the vendor host the token may be injected into. Parsed from
   * `EGRESS_MANAGED_IDENTITY_CONNECTIONS` as comma-separated `name=host-suffix`
   * pairs (e.g. `foundry=contoso.services.ai.azure.com` — the account host, not
   * the shared zone). Empty (the default) disables the mint path entirely —
   * resolution is then DB-only, exactly as before.
   */
  managedIdentityConnections: ManagedIdentityConnectionRule[];
  /**
   * Entra resource/audience the minted token is for, from
   * `EGRESS_MANAGED_IDENTITY_RESOURCE`; undefined = the Foundry default
   * (`https://ai.azure.com`, FOUNDRY_TOKEN_RESOURCE). An escape hatch for the
   * live spike and sovereign clouds, validated as a bare https origin.
   */
  managedIdentityResource?: string;
  /** Permit private/loopback targets — dev/test only; refused in production. */
  allowPrivate: boolean;
  /**
   * Extra CIDR ranges the SSRF filter refuses, from `EGRESS_EXTRA_BLOCKED_CIDRS`.
   * Empty means built-in ranges only. Bypassed by `allowPrivate` like the built-in list.
   */
  extraBlockedCidrs: ParsedCidr[];
  /**
   * Permit injecting a connection secret into a cleartext `http://` target —
   * dev/test only (loopback echo upstreams); refused in production. Egress is the
   * credential broker and must not leak a secret over the wire in cleartext
   * (issue #11, ADR-0005), so the injection path requires `https://` unless this
   * seam is explicitly opened.
   */
  allowInsecureConnection: boolean;
}

function required(env: NodeJS.ProcessEnv, key: string): string {
  const v = env[key];
  if (!v) throw new Error(`${key} is required`);
  return v;
}

/**
 * A positive-milliseconds env value with a fallback (the edge's
 * `requirePositiveMs`): a non-finite or non-positive interval would coerce to a
 * hot reconcile loop in `setTimeout`, so it is a boot error, not a runtime surprise.
 */
function requirePositiveMs(raw: string | undefined, fallback: number, name: string): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(
      `${name} must be a positive number of milliseconds (got ${JSON.stringify(raw)})`,
    );
  }
  return value;
}

/**
 * Parse `EGRESS_MANAGED_IDENTITY_CONNECTIONS`: comma-separated
 * `connection=host-suffix` pairs (`foundry=contoso.services.ai.azure.com` —
 * pin the account host, not the shared zone). Anything malformed is a boot
 * error, never a silently dropped rule — a rule that didn't parse and a rule
 * that was never written must not look alike in a 502. Host suffixes match
 * exactly or on a dot boundary (see the resolver).
 */
function parseManagedIdentityConnections(env: NodeJS.ProcessEnv): ManagedIdentityConnectionRule[] {
  const raw = env.EGRESS_MANAGED_IDENTITY_CONNECTIONS?.trim();
  if (!raw) return [];
  const seen = new Set<string>();
  return raw.split(",").map((entry) => {
    const eq = entry.indexOf("=");
    const connection = entry.slice(0, eq).trim();
    const hostSuffix = entry
      .slice(eq + 1)
      .trim()
      .toLowerCase();
    if (eq === -1 || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(connection)) {
      throw new Error(
        `EGRESS_MANAGED_IDENTITY_CONNECTIONS entry "${entry}" must be connection=host-suffix (kebab-case name)`,
      );
    }
    if (
      !/^[a-z0-9.-]+$/.test(hostSuffix) ||
      !hostSuffix.includes(".") ||
      hostSuffix.startsWith(".")
    ) {
      throw new Error(
        `EGRESS_MANAGED_IDENTITY_CONNECTIONS entry "${entry}" has an unusable host suffix ` +
          `(want a dotted DNS host like contoso.services.ai.azure.com — a bare TLD would match the world)`,
      );
    }
    if (seen.has(connection)) {
      throw new Error(`EGRESS_MANAGED_IDENTITY_CONNECTIONS lists "${connection}" twice`);
    }
    seen.add(connection);
    return { connection, hostSuffix };
  });
}

/**
 * Parse `EGRESS_MANAGED_IDENTITY_RESOURCE` — a bare https origin, nothing
 * else: the MI endpoint takes it as the `resource` query value, and a path or
 * query would ride along into the token request.
 */
function parseManagedIdentityResource(env: NodeJS.ProcessEnv): string | undefined {
  const raw = env.EGRESS_MANAGED_IDENTITY_RESOURCE?.trim();
  if (!raw) return undefined;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(
      "EGRESS_MANAGED_IDENTITY_RESOURCE must be an https origin (e.g. https://ai.azure.com)",
    );
  }
  if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash) {
    throw new Error(
      "EGRESS_MANAGED_IDENTITY_RESOURCE must be a bare https origin — no path, query, or fragment",
    );
  }
  return url.origin;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): EgressConfig {
  const instructionSecret = Buffer.from(required(env, "HELIX_INSTRUCTION_SECRET"));
  if (instructionSecret.byteLength < 32) {
    throw new Error("HELIX_INSTRUCTION_SECRET must be at least 32 bytes");
  }
  const exchangeSecret = Buffer.from(required(env, "HELIX_EXCHANGE_SECRET"));
  if (exchangeSecret.byteLength < 32) {
    throw new Error("HELIX_EXCHANGE_SECRET must be at least 32 bytes");
  }
  const databaseUrl = env.EGRESS_DATABASE_URL ?? env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error("EGRESS_DATABASE_URL or DATABASE_URL is required");
  }
  // Both flags open an SSRF/credential control ADR-0005 rests on, on the one
  // plane holding plaintext secrets — and with either set everything still
  // works, so a leaked-in value surfaces nowhere. Boot-fail instead, matching
  // the sibling dev seams on the other planes (EDGE_DEV_ALLOW_UNAUTHENTICATED,
  // PORTAL_ALLOW_SELF_APPROVE, the dev-token verifier).
  const allowPrivate = env.EGRESS_ALLOW_PRIVATE === "true";
  const allowInsecureConnection = env.EGRESS_ALLOW_INSECURE_CONNECTION === "true";
  if (env.NODE_ENV === "production") {
    for (const [key, on] of [
      ["EGRESS_ALLOW_PRIVATE", allowPrivate],
      ["EGRESS_ALLOW_INSECURE_CONNECTION", allowInsecureConnection],
    ] as const) {
      if (on) throw new Error(`${key} is a dev seam and is refused in production`);
    }
  }
  const extraBlockedCidrs = parseCidrList(
    env.EGRESS_EXTRA_BLOCKED_CIDRS,
    "EGRESS_EXTRA_BLOCKED_CIDRS",
  );

  return {
    port: Number(env.EGRESS_PORT ?? env.PORT ?? 8081),
    host: env.HOST ?? "0.0.0.0",
    databaseUrl,
    statementTimeoutMs: Number(env.EGRESS_STATEMENT_TIMEOUT_MS ?? DEFAULT_STATEMENT_TIMEOUT_MS),
    providersReconcileIntervalMs: requirePositiveMs(
      env.EGRESS_PROVIDERS_RECONCILE_INTERVAL_MS,
      60_000,
      "EGRESS_PROVIDERS_RECONCILE_INTERVAL_MS",
    ),
    retireSweepIntervalMs: requirePositiveMs(
      env.EGRESS_RETIRE_SWEEP_INTERVAL_MS,
      60_000,
      "EGRESS_RETIRE_SWEEP_INTERVAL_MS",
    ),
    instructionSecret,
    exchangeSecret,
    keyVaultUrl: env.AZURE_KEY_VAULT_URL || undefined,
    delegatedKeyVaultUrl: env.AZURE_DELEGATED_KEY_VAULT_URL || undefined,
    devKeyPath: env.DEV_SECRETS_KEK_FILE || undefined,
    limits: {
      maxBodyBytes: Number(env.EGRESS_MAX_BODY_BYTES ?? 10 * 1024 * 1024),
      // 120s, not 30s: this bounds the vendor dispatcher's headers/body
      // timeouts on the proxied LLM path, where a reasoning model can think
      // well past 30s before its first byte. The connect half keeps its own
      // tighter bound via the validating connector's budget.
      timeoutMs: Number(env.EGRESS_TIMEOUT_MS ?? 120_000),
    },
    managedIdentityConnections: parseManagedIdentityConnections(env),
    managedIdentityResource: parseManagedIdentityResource(env),
    allowPrivate,
    extraBlockedCidrs,
    allowInsecureConnection,
  };
}
