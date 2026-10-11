import {
  applyDeltas,
  captureSnapshot,
  CapabilitiesSchema,
  classifyChange,
  fetchOriginKey,
  maxRisk,
  parseFetchOriginKey,
  touchedAreas,
  type Capabilities,
  type Delta,
  type ManifestUpdateResult,
  type ProviderStamp,
  type Risk,
  type VisibilityState,
} from "@azx-pbc/shared";
import {
  Prisma,
  type ApprovalRequest as ApprovalRequestRow,
  type PrismaClient,
} from "../db/client.js";
import { capabilitiesFromRow, toManifest } from "../db/mappers.js";
import { manifestWithBindings, providerBindingStatuses } from "../connections/bindings.js";
import { AppError } from "../plugins/errors.js";
import { casPolicyWrite } from "../policy/policyWrite.js";

/**
 * Shared approvals plumbing (docs/design/approvals.md §2). The write-gate routes
 * (manifest, visibility, origin-grant) open requests; the approvals route
 * applies them. Both go through this module so the row shape and the paired
 * audit events stay in lockstep.
 *
 * Every function takes a Prisma transaction client so the request row and its
 * audit event commit atomically with the surrounding effective-state write.
 */
export type Tx = Prisma.TransactionClient;

const EMPTY_CAPABILITIES: Capabilities = { mcp: [], externalOrigins: [] };

export interface OpenRequestArgs {
  appId: string;
  /** The elevated subset of a change (baseline deltas commit separately). */
  deltas: Delta[];
  risk: Risk;
  /** Effective values of the touched areas at request time (conflict detect). */
  baseSnapshot: Record<string, unknown>;
  /** The requester's identity half — their `oid` (ADR-0048). What the guards compare. */
  requestedOid: string;
  /** The requester's display half (`actor.sub`) — rendered and audited, never compared. */
  requestedBy: string;
  reason?: string;
}

/** Insert a pending request + its `approval.request` audit event. Returns the id. */
export async function createApprovalRequest(tx: Tx, args: OpenRequestArgs): Promise<string> {
  const created = await tx.approvalRequest.create({
    data: {
      appId: args.appId,
      status: "pending",
      risk: args.risk,
      deltas: args.deltas as unknown as Prisma.InputJsonValue,
      baseSnapshot: args.baseSnapshot as unknown as Prisma.InputJsonValue,
      requestedOid: args.requestedOid,
      requestedBy: args.requestedBy,
      reason: args.reason ?? null,
    },
  });
  await tx.auditEvent.create({
    data: {
      appId: args.appId,
      actor: args.requestedBy,
      action: "approval.request",
      metadata: {
        requestId: created.id,
        risk: args.risk,
        deltas: args.deltas as unknown as Prisma.InputJsonValue,
      },
    },
  });
  return created.id;
}

/**
 * Compare-and-swap the `pending → terminal` transition (docs/design/approvals.md §5).
 *
 * The status check has to *be* the write. Read-then-branch inside a READ COMMITTED
 * transaction is not a guard: two decisions both read `pending`, and `update` by id
 * re-checks only `id`, so the later one overwrites the earlier's status. On approve
 * that left the request `withdrawn` while the capability it granted stayed live on
 * the `apps` row — the request row said the grant was pulled and the edge served it
 * anyway. Guarding on `status` here means the loser matches zero rows:
 * Postgres re-evaluates the WHERE after the row lock is released.
 *
 * `claimed === false` means another decision landed first, and the caller must apply
 * nothing. Callers pass that row to {@link alreadyDecided}.
 */
export type Claim =
  | { claimed: true; row: ApprovalRequestRow }
  | { claimed: false; row: ApprovalRequestRow | null };

export async function claimPendingRequest(
  tx: Tx,
  id: string,
  data: Prisma.ApprovalRequestUpdateManyMutationInput,
): Promise<Claim> {
  const { count } = await tx.approvalRequest.updateMany({
    where: { id, status: "pending" },
    data,
  });
  // updateMany returns a count, not the row — same shape as the secret-rotation
  // CAS in routes/secrets.ts. On the winning path the row lock is held, so the
  // re-read cannot miss; on the losing path it returns whoever won.
  const row = await tx.approvalRequest.findUnique({ where: { id } });
  if (count === 1) {
    if (!row) throw new AppError("not_found", `approval request "${id}" not found`);
    return { claimed: true, row };
  }
  return { claimed: false, row };
}

/**
 * Resolve a request that is already decided. Repeating a decision that already
 * landed stays the documented idempotent no-op (§5) — a second click must not be
 * an error. A *different* outcome is a 409: the caller asked for a transition that
 * did not happen, and answering 200 would tell them the opposite of what is stored.
 *
 * `landed` is every status the calling route can legitimately have produced, not
 * just the one it asked for. Approve is the reason it is a set: a stale request
 * bounces to `needs_changes` and answers 200, so replaying that same call — a
 * client timeout, a double-click — has to be a no-op too. Answering 409 there
 * would report a conflict against a decision the caller itself made.
 */
export function alreadyDecided(
  row: ApprovalRequestRow | null,
  landed: readonly string[],
): ApprovalRequestRow {
  if (!row) throw new AppError("not_found", "approval request not found");
  if (landed.includes(row.status)) return row;
  throw new AppError(
    "conflict",
    `approval request "${row.id}" was already ${row.status} — re-read it and retry`,
    { status: row.status },
  );
}

/**
 * The provider refs of a filing's elevated deltas — the `fetch.origins[+…]`
 * adds whose canonical key is provider-bound. Other delta shapes (removals,
 * keyless/secret-bound adds, scalars) never carry a provider.
 */
function providerRefOfDelta(d: Delta): string | null {
  if (typeof d.to !== "string" || !d.path.startsWith("fetch.origins[+")) return null;
  return parseFetchOriginKey(d.to).provider ?? null;
}

/**
 * Validate every provider-bound origin a requested manifest declares against
 * the provider rows: the declared origin must be one of THAT
 * provider's permitted API destinations (`apiOrigins`) in the applicable
 * environment, and the provider must exist. A manifest binding is
 * env-agnostic — it resolves in the caller's tier at call time — so every
 * env-partitioned row under the ref must permit the origin; a ref with no row
 * at all binds nothing and is refused. Failing this refuses the whole save
 * before any request is opened.
 */
async function validateProviderBindings(tx: Tx, requested: unknown): Promise<void> {
  const caps = CapabilitiesSchema.parse(requested);
  const refs = [
    ...new Set(
      (caps.fetch?.origins ?? [])
        .map((o) => o.provider)
        .filter((ref): ref is string => ref !== undefined),
    ),
  ];
  if (refs.length === 0) return;

  const rows = await tx.connectionProvider.findMany({ where: { ref: { in: refs } } });
  const rowsByRef = new Map<string, { env: string; apiOrigins: unknown }[]>();
  for (const row of rows) {
    const list = rowsByRef.get(row.ref) ?? [];
    list.push({ env: row.env, apiOrigins: row.apiOrigins });
    rowsByRef.set(row.ref, list);
  }

  for (const o of caps.fetch?.origins ?? []) {
    if (o.provider === undefined) continue;
    // The provider's destinations are canonical origins (canonicalised at
    // write); reduce the declared origin the same way so the comparison is
    // canonical-to-canonical.
    const declared = new URL(o.origin).origin;
    const providerRows = rowsByRef.get(o.provider) ?? [];
    if (providerRows.length === 0) {
      throw new AppError(
        "validation_failed",
        `origin "${o.origin}" is bound to provider "${o.provider}", but no provider with that reference is configured`,
      );
    }
    for (const row of providerRows) {
      const destinations = Array.isArray(row.apiOrigins) ? (row.apiOrigins as string[]) : [];
      if (!destinations.includes(declared)) {
        throw new AppError(
          "validation_failed",
          `origin "${o.origin}" is not one of provider "${o.provider}"'s permitted API destinations in the ${row.env} environment`,
        );
      }
    }
  }
}

/**
 * Stamp a filing's elevated deltas: every delta carries the app's
 * visibility **at filing** (`publicApp` — the warning is data on
 * the request, so the queue card never fetches the app), and provider-bound
 * origin adds carry one {@link ProviderStamp} per env-partitioned provider row
 * under the bound ref — the apply-time conflict's comparison half.
 */
async function stampElevatedDeltas(tx: Tx, deltas: Delta[], publicApp: boolean): Promise<Delta[]> {
  const refs = new Set<string>();
  for (const d of deltas) {
    const ref = providerRefOfDelta(d);
    if (ref !== null) refs.add(ref);
  }
  const stampsByRef = new Map<string, ProviderStamp[]>();
  if (refs.size > 0) {
    const rows = await tx.connectionProvider.findMany({ where: { ref: { in: [...refs] } } });
    for (const row of rows) {
      const list = stampsByRef.get(row.ref) ?? [];
      list.push({
        ref: row.ref,
        env: row.env === "dev" ? "dev" : "prod",
        providerId: row.id,
        revision: row.revision,
      });
      stampsByRef.set(row.ref, list);
    }
  }
  return deltas.map((d) => {
    const ref = providerRefOfDelta(d);
    const stamps = ref === null ? [] : (stampsByRef.get(ref) ?? []);
    return {
      ...d,
      publicApp,
      ...(stamps.length > 0 ? { providerStamps: stamps } : {}),
    };
  });
}

/**
 * The re-stamp rule: a provider-bound origin the request
 * still declares but whose approved stamps are ALL stale re-elevates **even
 * though the value is unchanged**. This is the recovery path the sensitive-edit
 * invalidation's revision bump leaves open — without it, a stale
 * binding ("Connection not available" at consult, the SPA's Reapproval-needed
 * badge) could never be repaired: the classifier diffs by `fetchOriginKey`, so
 * an unchanged binding produces no delta, files no request, and no fresh stamp
 * is ever filed. The resubmit IS the re-blessing: the owner re-asserts the
 * binding against the provider's new revision, and an administrator approves
 * the re-add exactly like a first grant (same high-risk class — the provider's
 * new configuration is what gets blessed).
 *
 * Bindings the classifier already delta'd (a changed origin key — the normal
 * add path) are skipped: those deltas were stamped at classification. Removed
 * bindings never appear in the requested state and are never re-elevated —
 * dropping a grant stays baseline and immediate.
 *
 * Returns the synthesized deltas, empty when every requested binding is
 * effective (the common resave — a no-op save must not queue requests).
 */
async function restampStaleBindings(
  tx: Tx,
  appId: string,
  requested: Capabilities,
  classified: Delta[],
): Promise<Delta[]> {
  const bound = (requested.fetch?.origins ?? []).filter((o) => o.provider !== undefined);
  if (bound.length === 0) return [];

  // Only synthesize what the classifier did not already emit as an add —
  // those carry fresh stamps from `stampElevatedDeltas` down-stream.
  const classifiedAdds = new Set(
    classified.filter((d) => d.path.startsWith("fetch.origins[+")).map((d) => d.path),
  );
  const candidates = bound.filter((o) => {
    const key = `fetch.origins[+${fetchOriginKey(o)}]`;
    return !classifiedAdds.has(key);
  });
  if (candidates.length === 0) return [];

  const statuses = await providerBindingStatuses(tx, appId, requested);
  const stale = new Set(statuses.filter((s) => !s.effective).map((s) => s.origin));
  return candidates
    .filter((o) => stale.has(o.origin))
    .map((o) => ({ path: `fetch.origins[+${fetchOriginKey(o)}]`, to: fetchOriginKey(o) }));
}

/**
 * The capability write-gate (docs/design/approvals.md §3): split a requested
 * capability change into baseline deltas (committed now) and elevated deltas
 * (bundled into one pending request), in a single transaction. Shared by the
 * manifest PUT and the one-click origin-grant route.
 *
 * Provider bindings extend the gate: the requested state is first
 * validated against the provider rows ({@link validateProviderBindings} — a
 * binding whose origin the provider does not serve refuses the whole save), and
 * the elevated bundle is stamped at filing ({@link stampElevatedDeltas} — the
 * provider stamps and the app's visibility, both read inside this transaction).
 * The re-stamp amendment: a binding whose stamps went stale (a sensitive
 * provider edit's revision bump) re-elevates on resubmit via
 * {@link restampStaleBindings} — the one recovery path the invalidation leaves.
 *
 * `mutate` receives the effective capabilities **as read inside the transaction**,
 * which is what makes a relative change (the origin grant's array append) land on
 * the committed value rather than on a pre-image the route read earlier. A write
 * that does change the blob then CASes on `policyVersion`, so a concurrent writer
 * cannot be clobbered; an elevated-only change writes nothing at all.
 */

/**
 * Classify create-time capabilities against the empty effective state, apply
 * baseline deltas, and open one approval request for the elevated bundle.
 * Called from `POST /api/v1/apps` inside the create transaction.
 */
export async function gateCapabilitiesAtCreate(
  tx: Tx,
  opts: {
    appId: string;
    requested: Capabilities;
    visibility: VisibilityState;
    actor: string;
    actorOid: string;
  },
): Promise<{ applied: Capabilities; baselineDeltas: Delta[]; pending: string | null }> {
  await validateProviderBindings(tx, opts.requested);
  const { baselineDeltas, elevatedDeltas, risk } = classifyChange(
    EMPTY_CAPABILITIES,
    opts.requested,
  );
  const applied = applyDeltas(EMPTY_CAPABILITIES, baselineDeltas);
  let pending: string | null = null;
  if (elevatedDeltas.length > 0) {
    const stamped = await stampElevatedDeltas(
      tx,
      elevatedDeltas,
      opts.visibility.mode === "public",
    );
    const baseSnapshot = captureSnapshot(applied, opts.visibility, touchedAreas(elevatedDeltas));
    pending = await createApprovalRequest(tx, {
      appId: opts.appId,
      deltas: stamped,
      risk,
      baseSnapshot,
      requestedOid: opts.actorOid,
      requestedBy: opts.actor,
    });
  }
  return { applied, baselineDeltas, pending };
}

export async function applyCapabilityChange(
  prisma: PrismaClient,
  opts: {
    appId: string;
    mutate: (effective: Capabilities) => Capabilities;
    /** The actor's display half (`actor.sub`) — audit attribution. */
    actor: string;
    /** The actor's identity half (`actor.oid`, ADR-0048) — requestedOid. */
    actorOid: string;
    reason?: string;
  },
): Promise<ManifestUpdateResult> {
  const { updated, pending, baselineDeltas } = await prisma.$transaction(async (tx) => {
    const row = await tx.app.findUniqueOrThrow({ where: { id: opts.appId } });
    const effective = capabilitiesFromRow(row);
    const requested = opts.mutate(effective);
    // Refuse an invalid binding before classifying or writing anything: no
    // baseline commit, no request.
    await validateProviderBindings(tx, requested);
    const {
      baselineDeltas,
      elevatedDeltas,
      risk: classifiedRisk,
    } = classifyChange(effective, requested);
    // The re-stamp amendment: a still-requested binding whose approved stamps
    // went stale re-elevates on resubmit — the recovery path the sensitive-edit
    // invalidation leaves open (see restampStaleBindings).
    const restampedDeltas = await restampStaleBindings(tx, row.id, requested, elevatedDeltas);
    const elevated = [...elevatedDeltas, ...restampedDeltas];
    const risk = restampedDeltas.length > 0 ? maxRisk([classifiedRisk, "high"]) : classifiedRisk;
    // Apply only the baseline deltas now; elevated ones wait for approval.
    const applied = applyDeltas(effective, baselineDeltas);

    // Only write when something actually changes. With no baseline deltas `applied`
    // *is* `effective`, and writing it back would CAS — turning two elevated-only
    // requests (say two origin grants filed off the Violations screen) into a
    // conflict over a value neither of them is changing.
    let updated = row;
    if (baselineDeltas.length > 0) {
      updated = await casPolicyWrite(tx, row, {
        capabilities: applied as unknown as Prisma.InputJsonValue,
      });
      await tx.auditEvent.create({
        data: {
          appId: row.id,
          actor: opts.actor,
          action: "app.manifest.set",
          metadata: { applied: baselineDeltas as unknown as Prisma.InputJsonValue },
        },
      });
    }
    let pending: string | null = null;
    if (elevated.length > 0) {
      // Stamp at filing, inside the txn that reads the visibility and the
      // provider rows — the stamps must describe the state the filer saw.
      const stamped = await stampElevatedDeltas(tx, elevated, row.visibilityMode === "public");
      // Snapshot the post-baseline state of the touched areas so a later approve
      // can detect a value that moved underneath the request.
      const baseSnapshot = captureSnapshot(
        applied,
        { mode: row.visibilityMode, groupIds: row.visibilityGroupIds },
        touchedAreas(elevated),
      );
      pending = await createApprovalRequest(tx, {
        appId: row.id,
        deltas: stamped,
        risk,
        baseSnapshot,
        requestedOid: opts.actorOid,
        requestedBy: opts.actor,
        reason: opts.reason,
      });
    }
    return { updated, pending, baselineDeltas };
  });

  return {
    manifest: await manifestWithBindings(prisma, opts.appId, toManifest(updated)),
    applied: baselineDeltas,
    pending,
  };
}
