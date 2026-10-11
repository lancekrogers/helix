import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Span } from "@opentelemetry/api";
import { z } from "zod";
import {
  CapabilitiesSchema,
  ConnectionProviderSchema,
  CONSENT_ATTEMPT_TTL_SECONDS,
  type CancelRequest,
  type CancelResponse,
  type ConnectionStatusRequest,
  type ConnectionStatusResponse,
  type ConsultRequest,
  type ConsultResponse,
  DeltaSchema,
  type Env,
  isProviderBindingEffective,
  parseFetchOriginKey,
  type ProviderStamp,
} from "@azx-pbc/shared";
import {
  ATTR_APP_ID,
  ATTR_APP_SLUG,
  ATTR_CONSENT_OPERATION,
  ATTR_CONSENT_SWEEP_REMOVED,
  ATTR_OUTCOME,
  ATTR_PROVIDER_REF,
  SPAN_CONSENT_CANCEL,
  SPAN_CONSENT_CLAIM,
  SPAN_CONSENT_CONSULT,
  SPAN_CONSENT_REDEEM,
  SPAN_CONSENT_STATUS,
  SPAN_CONSENT_SWEEP,
} from "@azx-pbc/shared/telemetry";
import type { SecretStore } from "@azx-pbc/secret-store";
import { Prisma, type PrismaClient } from "../db/client.js";
import { AppError } from "../plugins/errors.js";
import { isUniqueViolation } from "../db/errors.js";
import { withSpan, instruments } from "../telemetry.js";

/**
 * The consent-flow state machine (ADR-0031 amendment item 6 — the control
 * plane owns all
 * consent-flow state): the start consult the edge's start route and the dev
 * gateway call, the own-attempts-only cancel the helper's acknowledgement
 * rides, the claim-shaped probe the callback redeems an attempt with, the dev
 * journey's nonce redemption, the expiry sweep, and the read-only
 * connection-status read the app-facing status route forwards to (ADR-0031 as
 * amended — consult gates 1–4, no attempt write, no custody open). The routes
 * (`routes/connectionsInternal.ts`, `routes/connectionsPages.ts`) authorize
 * their calls and parse the shared contracts; every state decision lives
 * here.
 *
 * **The edge writes nothing.** `helix_edge` holds no grant on
 * `connection_consent_attempts` — every write in this file
 * happens under the portal's own role, which is the whole reason the consult
 * exists.
 */

/** The consent/status identity union's tier — pinned here, never a wire field. */
function identityEnv(
  identity: ConsultRequest["identity"] | ConnectionStatusRequest["identity"],
): Env {
  return identity.kind === "dev" ? "dev" : "prod";
}

/** The principal a connection and an attempt key to, per identity kind. */
function identityOid(
  identity: ConsultRequest["identity"] | ConnectionStatusRequest["identity"],
): string {
  return identity.kind === "dev" ? identity.developerOid : identity.userOid;
}

/** One counter add for a consent operation — bounded dims, never identity. */
function count(
  operation: "consult" | "cancel" | "claim" | "sweep" | "redeem" | "status",
  outcome: string,
): void {
  instruments().consentOperations.add(1, {
    [ATTR_CONSENT_OPERATION]: operation,
    [ATTR_OUTCOME]: outcome,
  });
}

const FRESH_BYTES = 32;

/** RFC 7636 §4.1: 43+ unreserved characters — base64url of 32 random bytes. */
function newVerifier(): string {
  return randomBytes(FRESH_BYTES).toString("base64url");
}

/** RFC 7636 §4.2: base64url(SHA256(verifier)) — the S256 challenge. */
export function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

/**
 * Assemble the vendor authorize URL from a provider's configuration plus the
 * attempt's protocol state — the ONE assembly both the consult (below) and
 * the dev journey's nonce redemption
 * use, so the two cannot drift. Only OAuth protocol parameters ride it: the
 * client secret stays sealed, the PKCE verifier stays server-side (only its
 * S256 challenge enters the URL), and no token or bearer material is ever
 * appended.
 */
function assembleAuthorizeUrl(opts: {
  authorizeEndpoint: string;
  clientId: string;
  requestedScopes: readonly string[];
  codeVerifier: string;
  state: string;
  callbackUrl: string;
}): string {
  const url = new URL(opts.authorizeEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", opts.clientId);
  url.searchParams.set("redirect_uri", opts.callbackUrl);
  url.searchParams.set("state", opts.state);
  url.searchParams.set("code_challenge", pkceChallenge(opts.codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");
  if (opts.requestedScopes.length > 0) {
    url.searchParams.set("scope", opts.requestedScopes.join(" "));
  }
  return url.toString();
}

/** The stored provider row through its one shared definition (dates → ISO). */
function parseProviderRow(row: {
  id: string;
  ref: string;
  kind: string;
  displayName: string;
  authorizeEndpoint: string;
  tokenEndpoint: string;
  requestedScopes: unknown;
  apiOrigins: unknown;
  tokenPlacement: unknown;
  env: string;
  clientIdMaterial: string;
  clientSecretMaterial: string;
  revision: number;
  createdAt: Date;
  updatedAt: Date;
}) {
  return ConnectionProviderSchema.parse({
    ...row,
    env: row.env === "dev" ? "dev" : "prod",
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  });
}

/**
 * The provider stamps an approved request filed for provider-bound origin
 * adds under one ref. A malformed deltas record parses as no stamps — a
 * broken approval row must fail the consult closed (`not_available`), never
 * grant consent off an unreadable grant.
 */
function stampsFor(deltas: unknown, ref: string): { env: Env; stamp: ProviderStamp }[] {
  const parsed = z.array(DeltaSchema).safeParse(deltas);
  if (!parsed.success) return [];
  const out: { env: Env; stamp: ProviderStamp }[] = [];
  for (const d of parsed.data) {
    if (typeof d.to !== "string" || !d.path.startsWith("fetch.origins[+")) continue;
    if (parseFetchOriginKey(d.to).provider !== ref) continue;
    for (const stamp of d.providerStamps ?? []) {
      if (stamp.ref === ref) out.push({ env: stamp.env, stamp });
    }
  }
  return out;
}

export async function consultConsent(
  prisma: PrismaClient,
  secretStore: SecretStore,
  req: ConsultRequest,
): Promise<ConsultResponse> {
  const env = identityEnv(req.identity);
  const userOid = identityOid(req.identity);

  return withSpan(
    SPAN_CONSENT_CONSULT,
    {
      [ATTR_CONSENT_OPERATION]: "consult",
      [ATTR_APP_SLUG]: req.appSlug,
      [ATTR_PROVIDER_REF]: req.providerRef,
    },
    async (span) => {
      try {
        const response = await consult(prisma, secretStore, req, env, userOid, span);
        span.setAttributes({ [ATTR_OUTCOME]: response.outcome });
        count("consult", response.outcome);
        return response;
      } catch (err) {
        span.setAttributes({ [ATTR_OUTCOME]: "error" });
        count("consult", "error");
        throw err;
      }
    },
  );
}

async function consult(
  prisma: PrismaClient,
  secretStore: SecretStore,
  req: ConsultRequest,
  env: Env,
  userOid: string,
  span: Span,
): Promise<ConsultResponse> {
  // 1 — consent is available only to an identified user of an authorized app
  // binding: binding approval/effectiveness first, then
  // connection status. The app is resolved by slug — the identity the edge's
  // host routing attests.
  const appRow = await prisma.app.findUnique({ where: { slug: req.appSlug } });
  if (!appRow) return { outcome: "not_available" };
  span.setAttributes({ [ATTR_APP_ID]: appRow.id });

  const caps = CapabilitiesSchema.parse(appRow.capabilities ?? {});
  if (!(caps.fetch?.origins ?? []).some((o) => o.provider === req.providerRef)) {
    // The binding never landed in the effective manifest — unapproved.
    return { outcome: "not_available" };
  }

  // 2 — the provider row must exist in the caller's tier (env is pinned by the
  // identity kind, never a request field).
  const providerRow = await prisma.connectionProvider.findUnique({
    where: { ref_env: { ref: req.providerRef, env } },
  });
  if (!providerRow) return { outcome: "not_available" };
  const provider = parseProviderRow(providerRow);

  // 3 — the binding is effective only when an APPROVED request's filing stamp
  // still matches the row's current identity — the binding-effectiveness
  // rule, consumed here
  // and never re-derived. A sensitive edit or a delete+recreate stale-dates
  // every stamp, and the consult reports not_available.
  const approved = await prisma.approvalRequest.findMany({
    where: { appId: appRow.id, status: "approved" },
    select: { deltas: true },
  });
  const effective = approved.some((r) =>
    stampsFor(r.deltas, req.providerRef).some(
      (s) => s.env === env && isProviderBindingEffective(s.stamp, provider),
    ),
  );
  if (!effective) return { outcome: "not_available" };

  // 4 — a working connection reports already-connected without being replaced:
  // no attempt, no vendor round-trip. Only `live` counts — a
  // reconnect-needed or invalidated row is replaceable through consent.
  const connection = await prisma.userConnection.findUnique({
    where: { userOid_providerId_env: { userOid, providerId: provider.id, env } },
  });
  if (connection?.status === "live") return { outcome: "already_connected" };

  // 5 — the client id is OAuth protocol state (it rides every authorize URL by
  // design); the client secret stays sealed and is never opened here. Opened
  // OUTSIDE any transaction — the vault call must never span the attempt write.
  const clientId = await secretStore.open(provider.clientIdMaterial);

  // 6 — the attempt write. The read-then-write above is made indivisible
  // against a connection landing mid-consult by re-asserting the no-live-
  // connection predicate IN the INSERT: a completion that commits between the
  // read and this statement inserts zero rows and the caller gets
  // already-connected, so a working connection is never raced into a
  // duplicate flow (the concurrency concern).
  const state = randomBytes(FRESH_BYTES).toString("base64url");
  const codeVerifier = newVerifier();
  const nonce = req.identity.kind === "dev" ? req.identity.nonce : null;
  const expiresAt = new Date(Date.now() + CONSENT_ATTEMPT_TTL_SECONDS * 1000);

  let inserted: Array<{ id: string }>;
  try {
    inserted = await prisma.$queryRaw<Array<{ id: string }>>(
      Prisma.sql`INSERT INTO connection_consent_attempts
          (id, state, "codeVerifier", "userOid", "providerId", "providerRevision",
           "appId", env, "openerOrigin", nonce, "expiresAt")
        SELECT ${randomUUID()}::uuid, ${state}, ${codeVerifier}, ${userOid},
               ${provider.id}::uuid, ${provider.revision}, ${appRow.id}::uuid, ${env},
               ${req.openerOrigin}, ${nonce}, ${expiresAt}
        WHERE NOT EXISTS (
          SELECT 1 FROM user_connections
          WHERE "userOid" = ${userOid} AND "providerId" = ${provider.id}::uuid
            AND "env" = ${env} AND status = 'live'
        )
        RETURNING id`,
    );
  } catch (err) {
    // A repeated `state` cannot occur (256-bit fresh); a repeated nonce can —
    // it is the dev journey's single-use value, so a replayed consult is a
    // conflict, not a second attempt.
    if (isUniqueViolation(err)) {
      throw new AppError("conflict", "consent attempt could not be created (replayed handoff)");
    }
    throw err;
  }
  if (inserted.length === 0) return { outcome: "already_connected" };

  // 7 — assemble the vendor authorize URL (the one shared assembly): only
  // OAuth protocol parameters, never credential material.
  const authorizeUrl = assembleAuthorizeUrl({
    authorizeEndpoint: provider.authorizeEndpoint,
    clientId,
    requestedScopes: provider.requestedScopes,
    codeVerifier,
    state,
    callbackUrl: req.callbackUrl,
  });
  return { outcome: "started", authorizeUrl };
}

/**
 * The connection-status read (ADR-0031 as amended): the consult's gates 1–4
 * with no attempt write, no custody open, and no vendor contact — the
 * read-only cousin the app-facing `GET /_api/connections/:ref/status` route
 * forwards to over the internal seam.
 *
 * The answer is Helix's own row state, and it collapses exactly the way the
 * delegated-call error table collapses: a `live` row is `connected`; every
 * other row state (reconnect-needed, invalidated, absent) is `not_connected`
 * — the same condition under which a provider-bound call answers 403
 * `connection_required`, and the remedy (Connect) is identical for all of
 * them. A `not_available` means one of the consult's own gates would refuse —
 * unknown app, a binding that never landed or went stale, a provider row
 * missing in the caller's tier — so the status route can never reveal
 * connection state for a provider the app does not effectively bind.
 */
export async function connectionStatus(
  prisma: PrismaClient,
  req: ConnectionStatusRequest,
): Promise<ConnectionStatusResponse> {
  const env = identityEnv(req.identity);
  const userOid = identityOid(req.identity);

  return withSpan(
    SPAN_CONSENT_STATUS,
    {
      [ATTR_CONSENT_OPERATION]: "status",
      [ATTR_APP_SLUG]: req.appSlug,
      [ATTR_PROVIDER_REF]: req.providerRef,
    },
    async (span) => {
      try {
        const response = await status(prisma, req, env, userOid, span);
        span.setAttributes({ [ATTR_OUTCOME]: response.status });
        count("status", response.status);
        return response;
      } catch (err) {
        span.setAttributes({ [ATTR_OUTCOME]: "error" });
        count("status", "error");
        throw err;
      }
    },
  );
}

async function status(
  prisma: PrismaClient,
  req: ConnectionStatusRequest,
  env: Env,
  userOid: string,
  span: Span,
): Promise<ConnectionStatusResponse> {
  // 1 — the app, resolved by slug (the identity the edge's host routing
  // attests). An unknown app is not_available, never a distinction an
  // unbound caller could mine.
  const appRow = await prisma.app.findUnique({ where: { slug: req.appSlug } });
  if (!appRow) return { status: "not_available" };
  span.setAttributes({ [ATTR_APP_ID]: appRow.id });

  // 2 — the binding must have landed in the effective manifest.
  const caps = CapabilitiesSchema.parse(appRow.capabilities ?? {});
  if (!(caps.fetch?.origins ?? []).some((o) => o.provider === req.providerRef)) {
    return { status: "not_available" };
  }

  // 3 — the provider row must exist in the caller's tier (env is pinned by
  // the identity kind, never a request field).
  const providerRow = await prisma.connectionProvider.findUnique({
    where: { ref_env: { ref: req.providerRef, env } },
  });
  if (!providerRow) return { status: "not_available" };
  const provider = parseProviderRow(providerRow);
  span.setAttributes({ [ATTR_PROVIDER_REF]: provider.ref });

  // 4 — binding effectiveness: an APPROVED request's filing stamp must still
  // match the row's current identity (the consult's rule, consumed here and
  // never re-derived). A sensitive edit or delete+recreate reads
  // not_available, the same answer a connect attempt would get.
  const approved = await prisma.approvalRequest.findMany({
    where: { appId: appRow.id, status: "approved" },
    select: { deltas: true },
  });
  const effective = approved.some((r) =>
    stampsFor(r.deltas, req.providerRef).some(
      (s) => s.env === env && isProviderBindingEffective(s.stamp, provider),
    ),
  );
  if (!effective) return { status: "not_available" };

  // 5 — the connection row. Only `live` counts — the same word the delegated
  // resolver keys on, so `connected` here is exactly the condition under
  // which the next provider-bound call dispatches (a dead token still says
  // connected; renewal runs invisibly at call time).
  const connection = await prisma.userConnection.findUnique({
    where: { userOid_providerId_env: { userOid, providerId: provider.id, env } },
  });
  if (connection?.status === "live") return { status: "connected" };
  return { status: "not_connected" };
}

/**
 * Acknowledge a closed popup (own-attempts-only): the attempt's
 * owning identity marks it cancelled, so a late completion cannot claim it.
 * The CAS makes the status check the write (the `claimPendingRequest`
 * pattern) — a cancel racing the callback's claim, a second cancel, or a
 * non-owner's call all lose and answer `not_cancellable`, indistinguishably
 * from "no such attempt". Consent already saved is a connection row, out of
 * cancel's reach.
 */
export async function cancelConsentAttempt(
  prisma: PrismaClient,
  req: CancelRequest,
): Promise<CancelResponse> {
  const env = identityEnv(req.identity);
  const userOid = identityOid(req.identity);

  return withSpan(SPAN_CONSENT_CANCEL, { [ATTR_CONSENT_OPERATION]: "cancel" }, async (span) => {
    let outcome: CancelResponse["outcome"];
    try {
      // Ownership pre-check; the CAS below re-asserts liveness, so only the
      // owner's call may even attempt the write, and anyone else's state
      // value gets the same answer an unknown one gets.
      const attempt = await prisma.connectionConsentAttempt.findUnique({
        where: { state: req.state },
      });
      const ownable =
        attempt !== null &&
        attempt.env === env &&
        attempt.userOid === userOid &&
        attempt.cancelledAt === null &&
        attempt.expiresAt.getTime() > Date.now();
      if (ownable) {
        const { count: claimed } = await prisma.connectionConsentAttempt.updateMany({
          where: { state: req.state, cancelledAt: null, expiresAt: { gt: new Date() } },
          data: { cancelledAt: new Date() },
        });
        outcome = claimed === 1 ? "cancelled" : "not_cancellable";
      } else {
        outcome = "not_cancellable";
      }
    } catch (err) {
      span.setAttributes({ [ATTR_OUTCOME]: "error" });
      count("cancel", "error");
      throw err;
    }
    span.setAttributes({ [ATTR_OUTCOME]: outcome });
    count("cancel", outcome);
    return { outcome };
  });
}

/** The claim's refusal reasons — what the callback's terminal pages key on. */
export type ConsentAttemptClaimRefusal = "not_found" | "expired" | "cancelled";

/** The claimed attempt: everything the callback's completion flow needs. */
export interface ClaimedConsentAttempt {
  id: string;
  state: string;
  codeVerifier: string;
  userOid: string;
  providerId: string;
  providerRevision: number;
  appId: string;
  env: Env;
  /** The completion message's exact target origin — recorded at consult. */
  openerOrigin: string;
  nonce: string | null;
}

export type ConsentAttemptClaim =
  | { claimed: true; attempt: ClaimedConsentAttempt }
  | { claimed: false; reason: ConsentAttemptClaimRefusal };

/**
 * The callback's claim-shaped probe (the callback route calls this): redeem an
 * attempt by `state`, atomically and single-use — the DELETE is the claim, so
 * exactly one concurrent completion can ever win, and the winner takes the
 * row with it. A cancelled or expired attempt (at/after the five-minute TTL)
 * refuses WITHOUT being deleted — "cancelled" / "expired" are the states the
 * callback renders — and an unknown or already-claimed state refuses as
 * "not_found". `openerOrigin` travels on the claimed attempt: the completion
 * message's target origin is the consult-recorded value and is derived by
 * nothing else.
 */
export async function claimConsentAttempt(
  prisma: PrismaClient,
  state: string,
): Promise<ConsentAttemptClaim> {
  return withSpan(SPAN_CONSENT_CLAIM, { [ATTR_CONSENT_OPERATION]: "claim" }, async (span) => {
    let claim: ConsentAttemptClaim;
    try {
      const rows = await prisma.$queryRaw<Array<ClaimedConsentAttempt>>(
        Prisma.sql`DELETE FROM connection_consent_attempts
          WHERE state = ${state} AND "cancelledAt" IS NULL AND "expiresAt" > now()
          RETURNING id, state, "codeVerifier", "userOid", "providerId",
                    "providerRevision", "appId", env, "openerOrigin", nonce`,
      );
      if (rows.length > 0) {
        const row = rows[0]!;
        claim = {
          claimed: true,
          attempt: { ...row, env: row.env === "dev" ? "dev" : "prod" },
        };
      } else {
        // Best-effort reason: a sweep racing this read turns "expired" into
        // "not_found". Both refuse, so the race only ever narrows a page's
        // wording, never widens an outcome.
        const row = await prisma.connectionConsentAttempt.findUnique({ where: { state } });
        claim = {
          claimed: false,
          reason: !row ? "not_found" : row.cancelledAt ? "cancelled" : "expired",
        };
      }
    } catch (err) {
      span.setAttributes({ [ATTR_OUTCOME]: "error" });
      count("claim", "error");
      throw err;
    }
    span.setAttributes({ [ATTR_OUTCOME]: claim.claimed ? "claimed" : claim.reason });
    count("claim", claim.claimed ? "claimed" : claim.reason);
    return claim;
  });
}

/** The nonce redemption's refusal reasons — what the entry page keys on. */
export type ConsentNonceRedeemRefusal =
  | "not_found"
  | "replayed"
  | "expired"
  | "cancelled"
  | "provider_changed";

export type ConsentNonceRedemption =
  | { redeemed: true; authorizeUrl: string }
  | { redeemed: false; reason: ConsentNonceRedeemRefusal };

/**
 * The dev journey's one-time handoff redemption (the nonce entry on the auth
 * host, proxied, redeemed
 * portal-side). The popup URL carries only the nonce; this is where it buys
 * the vendor redirect.
 *
 * **The redeem is one conditional UPDATE** — the indivisible claim rule: the
 * statement marks `nonceRedeemedAt` and returns the attempt in the same
 * breath, so exactly one concurrent redemption can ever win and a replayed
 * popup URL is refused after first use (the redemption's security property).
 * A cancelled or expired attempt refuses WITHOUT being redeemed, the same
 * posture the claim probe holds — a refusal consumes nothing that could
 * still complete.
 *
 * The vendor authorize URL is then **re-derived from the portal's stored
 * attempt data** — the attempt row (state, PKCE verifier, provider
 * id+revision) plus the provider row's configuration — through the one
 * shared {@link assembleAuthorizeUrl}. The URL is deliberately not stored on
 * the attempt: the verifier stays server-side and only its S256 challenge
 * enters the re-derived URL. A provider deleted or
 * edited since the attempt refuses (`provider_changed`) — an attempt
 * recorded against a revision must not send the user through configuration
 * that attempt never saw.
 *
 * `callbackUrl` is the caller's configured control-origin value
 * (`deployment.ts` `connectionsCallbackUrl` / `CONTROL_PUBLIC_BASE`): the
 * redemption has no edge call to supply it, and the consistency session
 * test-pins the same URL the edge expects for the deployment topology.
 */
export async function redeemConsentNonce(
  prisma: PrismaClient,
  secretStore: SecretStore,
  nonce: string,
  callbackUrl: string,
): Promise<ConsentNonceRedemption> {
  return withSpan(SPAN_CONSENT_REDEEM, { [ATTR_CONSENT_OPERATION]: "redeem" }, async (span) => {
    let result: ConsentNonceRedemption;
    try {
      result = await redeem(prisma, secretStore, nonce, callbackUrl, span);
      const outcome = result.redeemed ? "redeemed" : result.reason;
      span.setAttributes({ [ATTR_OUTCOME]: outcome });
      count("redeem", outcome);
      return result;
    } catch (err) {
      span.setAttributes({ [ATTR_OUTCOME]: "error" });
      count("redeem", "error");
      throw err;
    }
  });
}

async function redeem(
  prisma: PrismaClient,
  secretStore: SecretStore,
  nonce: string,
  callbackUrl: string,
  span: Span,
): Promise<ConsentNonceRedemption> {
  // 1 — the indivisible claim (above).
  const rows = await prisma.$queryRaw<
    Array<{
      state: string;
      codeVerifier: string;
      providerId: string;
      providerRevision: number;
      env: string;
    }>
  >(
    Prisma.sql`UPDATE connection_consent_attempts
      SET "nonceRedeemedAt" = now()
      WHERE nonce = ${nonce} AND "nonceRedeemedAt" IS NULL
        AND "cancelledAt" IS NULL AND "expiresAt" > now()
      RETURNING state, "codeVerifier", "providerId", "providerRevision", env`,
  );
  if (rows.length === 0) {
    // Best-effort reason (the claim probe's posture): a sweep racing this
    // read turns "expired" into "not_found". Every reason refuses, so the
    // race only ever narrows the operator's signal, never the page.
    const row = await prisma.connectionConsentAttempt.findUnique({
      where: { nonce },
      select: { nonceRedeemedAt: true, cancelledAt: true, expiresAt: true },
    });
    const reason: ConsentNonceRedeemRefusal = !row
      ? "not_found"
      : row.nonceRedeemedAt
        ? "replayed"
        : row.cancelledAt
          ? "cancelled"
          : row.expiresAt.getTime() <= Date.now()
            ? "expired"
            : "not_found";
    return { redeemed: false, reason };
  }
  const attempt = rows[0]!;

  // 2 — the provider row as of NOW, through its one shared definition. The
  // env must still match the attempt's tier: defense in depth behind the
  // consult's env-pinned resolution (a dev attempt must never redirect
  // through a prod registration, whatever row reorganization happens).
  const providerRow = await prisma.connectionProvider.findUnique({
    where: { id: attempt.providerId },
  });
  const provider = providerRow ? parseProviderRow(providerRow) : null;
  if (!provider || provider.revision !== attempt.providerRevision || provider.env !== attempt.env) {
    return { redeemed: false, reason: "provider_changed" };
  }
  span.setAttributes({ [ATTR_PROVIDER_REF]: provider.ref });

  // 3 — the client id is OAuth protocol state; the client secret stays
  // sealed and is never opened here. Opened AFTER the claim: a custody
  // failure burns this nonce (fail-closed) but can never race a second
  // redemption into a second redirect.
  const clientId = await secretStore.open(provider.clientIdMaterial);

  const authorizeUrl = assembleAuthorizeUrl({
    authorizeEndpoint: provider.authorizeEndpoint,
    clientId,
    requestedScopes: provider.requestedScopes,
    codeVerifier: attempt.codeVerifier,
    state: attempt.state,
    callbackUrl,
  });
  return { redeemed: true, authorizeUrl };
}

/**
 * Remove expired attempt rows (swept
 * portal-side; no material is involved: an attempt holds protocol state,
 * never credentials). Rows still inside their TTL — pending or cancelled —
 * are untouched. Returns the number removed. Interval-driven from
 * `server.ts` (the egress burn-sweep precedent: unref'd, cleared on close).
 */
export async function sweepExpiredConsentAttempts(prisma: PrismaClient): Promise<number> {
  return withSpan(SPAN_CONSENT_SWEEP, { [ATTR_CONSENT_OPERATION]: "sweep" }, async (span) => {
    try {
      const { count: removed } = await prisma.connectionConsentAttempt.deleteMany({
        where: { expiresAt: { lte: new Date() } },
      });
      span.setAttributes({ [ATTR_CONSENT_SWEEP_REMOVED]: removed, [ATTR_OUTCOME]: "ok" });
      count("sweep", "ok");
      return removed;
    } catch (err) {
      span.setAttributes({ [ATTR_OUTCOME]: "failed" });
      count("sweep", "failed");
      throw err;
    }
  });
}
