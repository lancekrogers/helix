import { Readable } from "node:stream";
import type { LlmChatRequest, LlmUsage, Env } from "@azx-pbc/shared";
import type { BlobGetOptions, BlobGetResult, BlobReader } from "../blob/client.js";
import type {
  ProxiedOriginCredential,
  RegistryEntry,
  RegistryFreshness,
  RegistryFreshnessReader,
  RegistryReader,
} from "../registry/projection.js";
import type { LlmProvider, LlmStreamEvent } from "../gateway/provider.js";
import { clampRecord } from "../gateway/usage.js";
import type { GatewayCallRecord, LlmSpend, UsageStore } from "../gateway/usage.js";
import type {
  AppDataStore,
  CollectionMeta,
  PutResult,
  SharedKeyMeta,
  SharedKeyPage,
  SharedWritePrecondition,
  UserKeyMeta,
  WritePrecondition,
} from "../gateway/data.js";
import { SHARED_LIST_PAGE, encodeListCursor } from "../gateway/data.js";
import type { MeterIdentity } from "../auth/gate.js";
import type { Session, SessionStore } from "../auth/sessions.js";
import type {
  PortalProvider,
  PortalProxyRequest,
  PortalProxyResponse,
} from "../routing/portalProvider.js";
import type {
  AuthorizeParams,
  ExchangeChecks,
  ExchangeOutcome,
  OidcClient,
  OidcIdentity,
} from "../auth/oidc.js";

/** A full RegistryEntry from a partial — internal visibility by default. */
export function registryEntry(overrides: Partial<RegistryEntry> & { slug: string }): RegistryEntry {
  return {
    appId: "00000000-0000-4000-8000-000000000000",
    archived: false,
    blobPrefix: null,
    visibilityMode: "internal",
    visibilityGroupIds: [],
    passwordHash: null,
    passwordSalt: null,
    llm: null,
    data: null,
    externalOrigins: [],
    // The one place the widened fetch-grant shape is restated for every edge
    // test: `connections` maps a canonical origin to exactly one credential
    // source (keyless | secret | provider — never both).
    fetch: {
      connections: new Map<string, ProxiedOriginCredential>(),
      requestsPerDay: null,
      shim: false,
    },
    offline: null,
    shim: null,
    ...overrides,
  };
}

/** In-memory registry for unit tests. */
export class FakeRegistry implements RegistryReader, RegistryFreshnessReader {
  #entries = new Map<string, RegistryEntry>();
  #loaded: boolean;
  /**
   * Mutable so a test can age a loaded registry mid-flight (`/health` degrades
   * off this). Defaults to "loaded just now", which keeps every existing
   * buildApp test reporting `ok`.
   */
  freshnessOverride: Partial<RegistryFreshness>;

  constructor(
    entries: RegistryEntry[] = [],
    opts: { loaded?: boolean; freshness?: Partial<RegistryFreshness> } = {},
  ) {
    for (const entry of entries) this.#entries.set(entry.slug, entry);
    this.#loaded = opts.loaded ?? true;
    this.freshnessOverride = opts.freshness ?? {};
  }

  getApp(slug: string): RegistryEntry | undefined {
    return this.#entries.get(slug);
  }

  isLoaded(): boolean {
    return this.#loaded;
  }

  freshness(): RegistryFreshness {
    const loaded = this.#loaded;
    return {
      loaded,
      lastSuccessfulLoadAt: loaded ? "2026-07-30T12:00:00.000Z" : null,
      staleForMs: loaded ? 0 : null,
      consecutiveLoadFailures: 0,
      lastLoadFailureAt: null,
      ...this.freshnessOverride,
    };
  }
}

export interface FakeBlob {
  body: Buffer | string;
  contentType?: string;
  etag?: string;
}

/** In-memory blob store mirroring UndiciBlobReader's result mapping. */
export class FakeBlobReader implements BlobReader {
  #blobs = new Map<string, Required<FakeBlob>>();
  /** Every key requested, in order — lets tests assert fallback behavior. */
  readonly requests: string[] = [];

  set(key: string, blob: FakeBlob): void {
    this.#blobs.set(key, {
      body: Buffer.isBuffer(blob.body) ? blob.body : Buffer.from(blob.body),
      contentType: blob.contentType ?? "application/octet-stream",
      etag: blob.etag ?? `"etag-${this.#blobs.size + 1}"`,
    });
  }

  async get(key: string, opts: BlobGetOptions): Promise<BlobGetResult> {
    this.requests.push(key);
    const blob = this.#blobs.get(key);
    if (!blob) return { kind: "not-found" };
    if (opts.ifNoneMatch && opts.ifNoneMatch === blob.etag) {
      return { kind: "not-modified", etag: blob.etag };
    }
    return {
      kind: "found",
      contentType: blob.contentType,
      contentLength: String(blob.body.length),
      etag: blob.etag,
      body: Readable.from(opts.method === "HEAD" ? [] : [blob.body]),
    };
  }

  async close(): Promise<void> {}
}

/**
 * Scripted LLM provider for unit/adversarial tests — never touches the network.
 * Yields the configured text deltas then a `done` event; `onDelta` lets a test
 * interleave or observe mid-stream (used to prove finish-in-flight).
 */
export class FakeLlmProvider implements LlmProvider {
  /** Requests seen, for assertions (model, messages, etc.). */
  readonly calls: LlmChatRequest[] = [];
  deltas: string[] = ["Hello", " world"];
  usage: LlmUsage = {
    inputTokens: 5,
    outputTokens: 2,
    cacheReadInputTokens: 0,
    cacheCreationInputTokens: 0,
  };
  stopReason = "end_turn";
  /** When set, yielded before the first delta (Anthropic `message_start` shape). */
  earlyUsage?: LlmUsage;
  /** When set, thrown after all deltas instead of yielding `done`. */
  errorAfterDeltas: Error | null = null;
  /** When set, stream() throws before yielding anything. */
  error: Error | null = null;
  /**
   * When set, blocks until the handler aborts the call, then throws this error
   * (simulates a silent upstream past request dispatch).
   */
  hangUntilAbort: Error | null = null;
  /** Awaited before each delta — a hook for interleaving/observation. */
  onDelta?: (index: number) => Promise<void> | void;
  /** Set when the handler's abort signal fired while the stream was open. */
  sawAbort = false;

  async *stream(req: LlmChatRequest, opts: { signal: AbortSignal }): AsyncIterable<LlmStreamEvent> {
    this.calls.push(req);
    if (this.error) throw this.error;
    if (this.hangUntilAbort) {
      await new Promise<void>((_resolve, reject) => {
        if (opts.signal.aborted) {
          reject(this.hangUntilAbort);
          return;
        }
        opts.signal.addEventListener("abort", () => reject(this.hangUntilAbort!), { once: true });
      });
    }
    if (opts.signal.aborted) this.sawAbort = true;
    else {
      opts.signal.addEventListener(
        "abort",
        () => {
          this.sawAbort = true;
        },
        { once: true },
      );
    }
    if (this.earlyUsage) {
      yield { type: "usage", usage: this.earlyUsage };
    }
    let index = 0;
    for (const text of this.deltas) {
      // Throw rather than return: a real provider surfaces a cancelled stream as
      // an AbortError, and the handler's catch is what has to cope with it.
      if (opts.signal.aborted) {
        const err = new Error("This operation was aborted");
        err.name = "AbortError";
        throw err;
      }
      await this.onDelta?.(index++);
      yield { type: "delta", text };
    }
    if (this.errorAfterDeltas) throw this.errorAfterDeltas;
    yield { type: "done", stopReason: this.stopReason, usage: this.usage };
  }

  async close(): Promise<void> {}
}

/** In-memory gateway ledger for tests; spend overrides drive quota decisions. */
export class FakeUsageStore implements UsageStore {
  readonly records: GatewayCallRecord[] = [];

  /** Override to force the daily LLM spend gate (micro-USD); else summed live. */
  spendTodayMicro?: number;
  /** Override to force the rolling-hour burst gate (micro-USD); else summed live. */
  spendHourMicro?: number;
  /** Override platform-wide today spend (micro-USD); else sum of every `llm` record. */
  platformSpendTodayMicro?: number;
  /** Override platform-wide hour spend (micro-USD); else same default as today. */
  platformSpendHourMicro?: number;
  /** When set, `platformLlmSpendMicroUsd` rejects with this error. */
  platformReadError?: Error;

  async llmSpendMicroUsd(): Promise<LlmSpend> {
    const summed = this.records
      .filter((r) => r.capability === "llm")
      .reduce((n, r) => n + (r.costMicroUsd ?? 0), 0);
    return {
      todayMicro: this.spendTodayMicro ?? summed,
      hourMicro: this.spendHourMicro ?? summed,
    };
  }

  async platformLlmSpendMicroUsd(env: Env): Promise<LlmSpend> {
    if (this.platformReadError) throw this.platformReadError;
    const summed = this.records
      .filter((r) => r.capability === "llm" && r.env === env)
      .reduce((n, r) => n + (r.costMicroUsd ?? 0), 0);
    return {
      todayMicro: this.platformSpendTodayMicro ?? summed,
      hourMicro: this.platformSpendHourMicro ?? summed,
    };
  }

  /** Override in a test to force the writesPerDay budget; defaults to the live count. */
  writesToday?: number;

  async dataWritesToday(): Promise<number> {
    if (this.writesToday !== undefined) return this.writesToday;
    return this.records.filter(
      (r) =>
        r.capability === "data" &&
        r.outcome === "ok" &&
        ["user.put", "collection.append", "shared.put"].includes(r.model),
    ).length;
  }

  /** Override in a test to force the requestsPerDay budget; defaults to the live count. */
  fetchToday?: number;

  async fetchRequestsToday(): Promise<number> {
    if (this.fetchToday !== undefined) return this.fetchToday;
    // Mirrors PgUsageStore's predicate: the platform's own pre-egress refusals
    // don't consume the budget, and `connection_required` — an egress outcome —
    // does. Keep the two in step — a fake that counts differently from the
    // real store makes the unit tests lie.
    return this.records.filter(
      (r) => r.capability === "fetch" && r.outcome !== "quota_blocked" && r.outcome !== "forbidden",
    ).length;
  }

  async record(raw: GatewayCallRecord): Promise<void> {
    // Clamp exactly as PgUsageStore does, so a test asserting on `records` sees
    // what the real store would have written — including the length caps.
    this.records.push(clampRecord(raw));
  }

  async close(): Promise<void> {}
}

/**
 * In-memory app-data store. Mirrors PgAppDataStore's caller-scoped contract:
 * keyed strictly by (appId, userOid, key), so a test can never accidentally
 * reach across the partition — the same property the RLS policy enforces in
 * Postgres. Like the real store, it has no collection-enumeration method.
 *
 * It also mirrors the real CAS semantics (ADR-0041): every row carries a
 * version that starts at 1 and increments per write, `ifMatch` against an
 * absent or moved row conflicts, and `ifNoneMatch` against an existing row
 * conflicts. A fake that ignored preconditions would make every handler test
 * assert a behaviour production does not have.
 */
export class FakeAppDataStore implements AppDataStore {
  readonly rows = new Map<string, { value: unknown; updatedAt: string; version: number }>();

  #k(appId: string, userOid: string, key: string): string {
    return `${appId} ${userOid} ${key}`;
  }

  async getUserKey(appId: string, userOid: string, key: string) {
    const row = this.rows.get(this.#k(appId, userOid, key));
    return row ? { value: row.value, version: String(row.version) } : null;
  }

  #put(mapKey: string, value: unknown, precondition: WritePrecondition): PutResult {
    const existing = this.rows.get(mapKey);
    const conflict = (): PutResult => ({
      kind: "conflict",
      // Mirrors the real store's post-conflict SELECT: the loser learns what
      // to CAS against next (null when the key is absent).
      currentVersion: existing ? String(existing.version) : null,
    });
    switch (precondition.kind) {
      case "ifMatch":
        if (!existing || String(existing.version) !== precondition.version) return conflict();
        break;
      case "ifNoneMatch":
        if (existing) return conflict();
        break;
      case "none":
        break;
    }
    const version = (existing?.version ?? 0) + 1;
    const updatedAt = new Date().toISOString();
    this.rows.set(mapKey, { value, updatedAt, version });
    return { kind: "ok", version: String(version), updatedAt };
  }

  async putUserKey(
    appId: string,
    userOid: string,
    key: string,
    value: unknown,
    _env: Env,
    precondition: WritePrecondition,
  ): Promise<PutResult> {
    return this.#put(this.#k(appId, userOid, key), value, precondition);
  }

  async deleteUserKey(appId: string, userOid: string, key: string): Promise<boolean> {
    return this.rows.delete(this.#k(appId, userOid, key));
  }

  async listUserKeys(appId: string, userOid: string): Promise<UserKeyMeta[]> {
    const prefix = `${appId} ${userOid} `;
    const out: UserKeyMeta[] = [];
    for (const [k, v] of this.rows) {
      if (k.startsWith(prefix)) out.push({ key: k.slice(prefix.length), updatedAt: v.updatedAt });
    }
    return out.sort((a, b) => a.key.localeCompare(b.key));
  }

  /** Appended collection items — write-only, mirroring the real store (no read API). */
  readonly collectionItems: {
    appId: string;
    collection: string;
    item: unknown;
    submitter: MeterIdentity | null;
    meta: CollectionMeta;
  }[] = [];

  async appendCollection(
    appId: string,
    collection: string,
    item: unknown,
    submitter: MeterIdentity | null,
    meta: CollectionMeta,
  ): Promise<void> {
    this.collectionItems.push({ appId, collection, item, submitter, meta });
  }

  #sharedKey(appId: string, key: string): string {
    return `${appId}  shared ${key}`;
  }

  async getShared(appId: string, key: string) {
    const row = this.rows.get(this.#sharedKey(appId, key));
    return row ? { value: row.value, version: String(row.version) } : null;
  }

  /**
   * Mirrors `PgAppDataStore.listShared` (ADR-0042): prefix filter, keyset
   * cursor, cap+1 lookahead. Sort and cursor predicate both compare the UTF-8
   * BYTES (`Buffer.compare`), not JS code units. Keys are printable ASCII
   * (ADR-0043), so the two orders coincide for anything creatable through the
   * API — the bytewise comparator is the backstop for out-of-band rows (seeded
   * straight at the store by tests, or written by a future bug), where
   * code-unit and bytewise order diverge above the BMP and the real store's
   * `COLLATE "C"` keyset is bytewise.
   */
  async listShared(appId: string, prefix: string, afterKey: string | null): Promise<SharedKeyPage> {
    // `#sharedKey(appId, "")` IS the shared-row key prefix for this app.
    const base = this.#sharedKey(appId, "");
    const bytewise = (a: string, b: string): number =>
      Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
    const matched: SharedKeyMeta[] = [];
    for (const [k, v] of this.rows) {
      if (!k.startsWith(base)) continue;
      const key = k.slice(base.length);
      if (!key.startsWith(prefix)) continue;
      if (afterKey !== null && bytewise(key, afterKey) <= 0) continue;
      matched.push({ key, version: String(v.version), updatedAt: v.updatedAt });
    }
    matched.sort((a, b) => bytewise(a.key, b.key));
    const keys = matched.slice(0, SHARED_LIST_PAGE);
    return matched.length > SHARED_LIST_PAGE
      ? { keys, nextCursor: encodeListCursor(keys.at(-1)!.key) }
      : { keys };
  }

  async putShared(
    appId: string,
    key: string,
    value: unknown,
    _env: Env,
    precondition: SharedWritePrecondition,
  ): Promise<PutResult> {
    return this.#put(this.#sharedKey(appId, key), value, precondition);
  }

  async close(): Promise<void> {}
}

/**
 * Scripted portal provider for the auth-host `/connections/*` proxy —
 * the `FakeEgress` of the portal-ward seam. Captures what
 * the edge forwards (method, target, the safelisted headers, the minted
 * internal token) and answers a fixed page.
 */
export class FakePortalProvider implements PortalProvider {
  readonly requests: PortalProxyRequest[] = [];
  status = 200;
  headers: Record<string, string | string[]> = { "content-type": "text/html; charset=utf-8" };
  body = "<html>served by portal</html>";
  /** When set, `proxy` rejects — the portal hop failed. */
  error: Error | null = null;

  async proxy(req: PortalProxyRequest): Promise<PortalProxyResponse> {
    this.requests.push(req);
    if (this.error) throw this.error;
    // Drain the request body the way a real consumer does — this is what
    // makes a body cap observable at the seam (the cap transform errors when
    // drained past its limit, which surfaces as a failed proxy call).
    if (req.body) {
      for await (const chunk of req.body) void chunk;
    }
    return {
      status: this.status,
      headers: this.headers,
      body: Readable.from([Buffer.from(this.body)]),
    };
  }

  async close(): Promise<void> {}
}

/**
 * Scripted IdP for unit tests. Mimics the real client's contract: the
 * callback URL's `state` must match the expected state, `code` must be
 * present, and `error=login_required` maps to interaction-required.
 */
export class FakeOidcClient implements OidcClient {
  ready = true;
  /** Identity a successful exchange yields. */
  identity: OidcIdentity = {
    oid: "oid-alice",
    displayName: "Alice Anders",
    name: "Alice Anders",
    email: "alice@azx.dev",
    groups: ["eng-team"],
  };
  /** When set, exchangeCode returns this unconditionally. */
  forcedOutcome: ExchangeOutcome | null = null;
  readonly authorizeRequests: AuthorizeParams[] = [];

  isReady(): boolean {
    return this.ready;
  }

  authorizationUrl(params: AuthorizeParams): string {
    this.authorizeRequests.push(params);
    const url = new URL("https://idp.example/authorize");
    url.searchParams.set("state", params.state);
    url.searchParams.set("nonce", params.nonce);
    url.searchParams.set("code_challenge", params.codeChallenge);
    if (params.prompt) url.searchParams.set("prompt", params.prompt);
    return url.toString();
  }

  async exchangeCode(callbackUrl: URL, checks: ExchangeChecks): Promise<ExchangeOutcome> {
    if (this.forcedOutcome) return this.forcedOutcome;
    const error = callbackUrl.searchParams.get("error");
    if (error) {
      return error === "login_required" ? { kind: "interaction-required" } : { kind: "invalid" };
    }
    const state = callbackUrl.searchParams.get("state");
    const code = callbackUrl.searchParams.get("code");
    if (!code || state === null || state !== checks.state) {
      return { kind: "invalid" };
    }
    return { kind: "ok", identity: this.identity };
  }
}

/** In-memory SessionStore mirroring PgSessionStore's semantics. */
export class FakeSessionStore implements SessionStore {
  /** Pending rows by id; redeemed rows also indexed by token hash. */
  readonly byId = new Map<string, Session & { tokenHash: string | null }>();

  async createPending(session: Session): Promise<void> {
    if (this.byId.has(session.id)) throw new Error(`duplicate session id ${session.id}`);
    this.byId.set(session.id, { ...session, tokenHash: null });
  }

  async createActive(session: Session, tokenHash: string): Promise<void> {
    if (this.byId.has(session.id)) throw new Error(`duplicate session id ${session.id}`);
    this.byId.set(session.id, { ...session, tokenHash });
  }

  async redeem(id: string, appId: string, tokenHash: string): Promise<boolean> {
    const row = this.byId.get(id);
    if (!row || row.tokenHash !== null || row.appId !== appId || row.expiresAt <= new Date()) {
      return false;
    }
    row.tokenHash = tokenHash;
    return true;
  }

  async lookup(tokenHash: string, appId: string): Promise<Session | null> {
    for (const row of this.byId.values()) {
      if (row.tokenHash === tokenHash && row.appId === appId && row.expiresAt > new Date()) {
        return {
          id: row.id,
          appId: row.appId,
          user: row.user,
          refreshDueAt: row.refreshDueAt,
          expiresAt: row.expiresAt,
        };
      }
    }
    return null;
  }

  async delete(tokenHash: string, appId: string): Promise<void> {
    for (const [id, row] of this.byId) {
      if (row.tokenHash === tokenHash && row.appId === appId) this.byId.delete(id);
    }
  }

  async sweep(): Promise<number> {
    return 0;
  }

  async close(): Promise<void> {}
}
