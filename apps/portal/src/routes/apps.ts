import type { FastifyInstance } from "fastify";
import {
  AppListScopeSchema,
  CapabilitiesSchema,
  CreateAppRequestSchema,
  type CreateAppResult,
  OriginGrantRequestSchema,
  PasswordCredentialResponseSchema,
  SetManifestRequestSchema,
  SetPasswordRequestSchema,
  SetVisibilityRequestSchema,
  UpdateAppRequestSchema,
  captureSnapshot,
  classifyVisibilityChange,
  visibilityGroupIds,
  visibilityLabel,
  touchedAreas,
  type ManifestUpdateResult,
  type VisibilityUpdateResult,
} from "@azx-pbc/shared";
import { authenticate, ownsApp, requireActor } from "../plugins/auth.js";
import { AppError } from "../plugins/errors.js";
import { passwordAppsAllowed, publicAppsAllowed } from "../policy/visibilityPolicy.js";
import { casPolicyWrite } from "../policy/policyWrite.js";
import { isUniqueViolation } from "../db/errors.js";
import {
  capabilitiesFromRow,
  toApp,
  toAppListItem,
  toManifest,
  visibilityToColumns,
  type DeployAggregates,
} from "../db/mappers.js";
import {
  applyCapabilityChange,
  createApprovalRequest,
  gateCapabilitiesAtCreate,
} from "../approvals/service.js";
import { manifestWithBindings } from "../connections/bindings.js";
import { Prisma } from "../db/client.js";
import {
  decryptPassword,
  encryptPassword,
  generatePassphrase,
  hashPassword,
} from "../access/password.js";
import { appPublicUrl } from "../deployment.js";

/** App registry routes: create, list, get (architecture §7). */
export async function appRoutes(app: FastifyInstance): Promise<void> {
  // Create an app. Mutating — requires the dev token.
  /**
   * `{ id: displayName }` for as many ids as the directory can name. Never
   * throws: see the caller's comment for why a failure here must not fail a
   * visibility write.
   */
  const resolveGroupNamesForAudit = async (ids: string[]): Promise<Record<string, string>> => {
    if (ids.length === 0) return {};
    try {
      const outcome = await app.directory.getGroups(ids);
      if (!outcome.available) return {};
      return Object.fromEntries(outcome.value.map((g) => [g.id, g.displayName]));
    } catch (err) {
      app.log.warn({ err }, "could not resolve group names for the visibility audit entry");
      return {};
    }
  };

  app.post("/api/v1/apps", { preHandler: authenticate }, async (req, reply) => {
    const body = CreateAppRequestSchema.parse(req.body);
    const actor = requireActor(req);
    // Operator policy: this deployment may forbid creating an open-surface app
    // (PORTAL_ALLOW_*_APPS). The edge enforces the same policy on serving.
    if (body.visibility.mode === "public" && !publicAppsAllowed()) {
      throw new AppError("forbidden", "public apps are disabled on this deployment");
    }
    if (body.visibility.mode === "password" && !passwordAppsAllowed()) {
      throw new AppError("forbidden", "password apps are disabled on this deployment");
    }
    const visibilityColumns = visibilityToColumns(body.visibility);
    // Best-effort, like the visibility route's: a name the directory could not
    // supply costs the audit row its names and nothing else.
    const createGroupNames = await resolveGroupNamesForAudit(visibilityColumns.visibilityGroupIds);
    const requested = CapabilitiesSchema.parse(body.capabilities ?? {});
    const visibilityState = {
      mode: body.visibility.mode,
      groupIds: visibilityColumns.visibilityGroupIds,
    };

    const result: CreateAppResult = await app.prisma.$transaction(async (tx) => {
      let row;
      try {
        row = await tx.app.create({
          data: {
            slug: body.slug,
            displayName: body.displayName,
            description: body.description ?? null,
            ownerId: actor.oid,
            ownerName: actor.name ?? null,
            ownerEmail: actor.email ?? null,
            ...visibilityColumns,
            // Baseline capabilities only; elevated grants wait on approval.
            capabilities: { mcp: [], externalOrigins: [] },
          },
        });
      } catch (err) {
        if (isUniqueViolation(err, "slug")) {
          throw new AppError("slug_taken", `slug "${body.slug}" is already taken`);
        }
        throw err;
      }

      const { applied, baselineDeltas, pending } = await gateCapabilitiesAtCreate(tx, {
        appId: row.id,
        requested,
        visibility: visibilityState,
        actor: actor.sub,
        actorOid: actor.oid,
      });

      if (baselineDeltas.length > 0) {
        row = await tx.app.update({
          where: { id: row.id },
          data: { capabilities: applied as unknown as Prisma.InputJsonValue },
        });
      }

      await tx.auditEvent.create({
        data: {
          appId: row.id,
          actor: actor.sub,
          action: "app.create",
          metadata: {
            slug: row.slug,
            visibility: visibilityLabel(body.visibility),
            ...(visibilityColumns.visibilityGroupIds.length > 0
              ? {
                  groupIds: visibilityColumns.visibilityGroupIds,
                  ...(Object.keys(createGroupNames).length > 0
                    ? { groupNames: createGroupNames }
                    : {}),
                }
              : {}),
          } as unknown as Prisma.InputJsonValue,
        },
      });

      const created = toApp(row);
      return { ...created, applied: baselineDeltas, pending };
    });

    reply.status(201).send(result);
  });

  /**
   * List apps. Read — sign-in required (any authenticated principal).
   *
   * `scope` is a **filter, not a permission gate.** `mine` narrows to the
   * caller's own apps because that is what the apps page defaults to showing;
   * `all` is open to every signed-in principal, exactly as this route has always
   * been. Browsing a colleague's apps is intended (one trusted org per
   * deployment — ADR-0028/ADR-0023), so do not read `mine` as a boundary or
   * bolt authorization onto it: read-scoping is v1 RBAC's job (ADR-0007).
   *
   * The deploy aggregates are rolled up in three fixed queries rather than per
   * row — the apps table needs live version, last deploy and version count for
   * every row, and fetching them per app is the 1+N this replaced.
   */
  app.get<{ Querystring: { scope?: string } }>(
    "/api/v1/apps",
    { preHandler: authenticate },
    async (req) => {
      const actor = requireActor(req);
      const scope = AppListScopeSchema.catch("mine").parse(req.query.scope ?? "mine");

      const rows = await app.prisma.app.findMany({
        where: scope === "mine" ? { ownerId: actor.oid } : {},
        orderBy: { createdAt: "asc" },
        include: { currentVersion: { select: { number: true } } },
      });
      if (rows.length === 0) return [];

      const appIds = rows.map((r) => r.id);
      const [totals, previews] = await Promise.all([
        app.prisma.version.groupBy({
          by: ["appId"],
          where: { appId: { in: appIds } },
          _max: { createdAt: true },
        }),
        app.prisma.version.groupBy({
          by: ["appId"],
          where: { appId: { in: appIds }, status: "preview" },
          _max: { number: true },
        }),
      ]);

      const byApp = new Map<string, Partial<DeployAggregates>>();
      for (const t of totals) {
        byApp.set(t.appId, { lastDeployAt: t._max.createdAt });
      }
      for (const p of previews) {
        byApp.set(p.appId, { ...byApp.get(p.appId), latestPreviewNumber: p._max.number });
      }

      return rows.map((row) =>
        toAppListItem(row, {
          ...byApp.get(row.id),
          liveVersionNumber: row.currentVersion?.number ?? null,
        }),
      );
    },
  );

  // Get one app by slug. Read — sign-in required.
  app.get<{ Params: { slug: string } }>(
    "/api/v1/apps/:slug",
    { preHandler: authenticate },
    async (req) => {
      const row = await app.prisma.app.findUnique({ where: { slug: req.params.slug } });
      if (!row) {
        throw new AppError("not_found", `app "${req.params.slug}" not found`);
      }
      return toApp(row);
    },
  );

  // Edit the registry record. Mutating — requires the owner. Partial body: only
  // the keys present are applied (absent = no change, `null` = clear), so the
  // schema can grow fields (displayName, …) without a second endpoint. Not a
  // policy write — the description is display-only state, so there is nothing
  // to CAS and nothing for the edge to project.
  app.patch<{ Params: { slug: string } }>(
    "/api/v1/apps/:slug",
    { preHandler: [authenticate, ownsApp] },
    async (req) => {
      const { description } = UpdateAppRequestSchema.parse(req.body);
      const actor = requireActor(req);
      const row = await app.prisma.app.findUnique({ where: { slug: req.params.slug } });
      if (!row) {
        throw new AppError("not_found", `app "${req.params.slug}" not found`);
      }
      const next = description === undefined ? row.description : description;
      if (next === row.description) {
        return toApp(row); // nothing to change — no write, no audit, no updatedAt bump
      }
      const updated = await app.prisma.app.update({
        where: { id: row.id },
        data: { description: next },
      });
      await app.prisma.auditEvent.create({
        data: {
          appId: row.id,
          actor: actor.sub,
          action: "app.update",
          // The new value rides along: the audit row is also the record of what
          // the description was set to (null means cleared), which the registry
          // row itself stops carrying the moment it is edited again.
          metadata: {
            description: next,
          } as unknown as Prisma.InputJsonValue,
        },
      });
      return toApp(updated);
    },
  );

  // Archive an app: the edge serves 410 + Clear-Site-Data for it (architecture
  // §7). Mutating — requires the dev token. Idempotent.
  app.post<{ Params: { slug: string } }>(
    "/api/v1/apps/:slug/archive",
    { preHandler: [authenticate, ownsApp] },
    async (req) => {
      const actor = requireActor(req);
      const row = await app.prisma.app.findUnique({ where: { slug: req.params.slug } });
      if (!row) {
        throw new AppError("not_found", `app "${req.params.slug}" not found`);
      }
      if (row.archivedAt) {
        return toApp(row); // already archived — idempotent
      }
      const updated = await app.prisma.app.update({
        where: { id: row.id },
        data: { archivedAt: new Date() },
      });
      await app.prisma.auditEvent.create({
        data: { appId: row.id, actor: actor.sub, action: "app.archive", metadata: {} },
      });
      return toApp(updated);
    },
  );

  // Un-archive an app. Mutating — requires the dev token. Idempotent.
  app.post<{ Params: { slug: string } }>(
    "/api/v1/apps/:slug/unarchive",
    { preHandler: [authenticate, ownsApp] },
    async (req) => {
      const actor = requireActor(req);
      const row = await app.prisma.app.findUnique({ where: { slug: req.params.slug } });
      if (!row) {
        throw new AppError("not_found", `app "${req.params.slug}" not found`);
      }
      if (!row.archivedAt) {
        return toApp(row); // not archived — idempotent
      }
      const updated = await app.prisma.app.update({
        where: { id: row.id },
        data: { archivedAt: null },
      });
      await app.prisma.auditEvent.create({
        data: { appId: row.id, actor: actor.sub, action: "app.unarchive", metadata: {} },
      });
      return toApp(updated);
    },
  );

  // Get an app's manifest (slug + visibility + capability grants, §6.3). Read —
  // sign-in required. Provider-bound origins carry their per-binding
  // effectiveness — computed here, on the read, so the SPA's
  // Reapproval-needed badge needs no second request.
  app.get<{ Params: { slug: string } }>(
    "/api/v1/apps/:slug/manifest",
    { preHandler: authenticate },
    async (req) => {
      const row = await app.prisma.app.findUnique({ where: { slug: req.params.slug } });
      if (!row) {
        throw new AppError("not_found", `app "${req.params.slug}" not found`);
      }
      return manifestWithBindings(app.prisma, row.id, toManifest(row));
    },
  );

  // Replace an app's capability grants (architecture §6.3). Mutating — bearer
  // token. Routed through the approvals write-gate (docs/design/approvals.md §3):
  // baseline deltas commit immediately (as before); elevated deltas (e.g. an
  // arbitrary MCP server, a budget above threshold) are bundled into one pending
  // ApprovalRequest and applied later on approve. The edge only ever sees the
  // committed effective state via its registry projection — it never learns a
  // request is open.
  app.put<{ Params: { slug: string } }>(
    "/api/v1/apps/:slug/manifest",
    { preHandler: [authenticate, ownsApp] },
    async (req): Promise<ManifestUpdateResult> => {
      const { capabilities: requested, reason } = SetManifestRequestSchema.parse(req.body);
      const actor = requireActor(req);
      const row = await app.prisma.app.findUnique({ where: { slug: req.params.slug } });
      if (!row) {
        throw new AppError("not_found", `app "${req.params.slug}" not found`);
      }
      // A full replace, so the requested value doesn't depend on the effective one
      // — but it is still classified against the state read inside the txn.
      return applyCapabilityChange(app.prisma, {
        appId: row.id,
        mutate: () => requested,
        actor: actor.sub,
        actorOid: actor.oid,
        reason,
      });
    },
  );

  // One-click origin grant from the Violations screen (docs/design/approvals.md
  // §6.2): add a single external origin through the same write-gate. Adding an
  // origin is always elevated, so this opens a med-risk request.
  app.post<{ Params: { slug: string } }>(
    "/api/v1/apps/:slug/access/origin",
    { preHandler: [authenticate, ownsApp] },
    async (req): Promise<ManifestUpdateResult> => {
      const { origin, reason } = OriginGrantRequestSchema.parse(req.body);
      const actor = requireActor(req);
      const row = await app.prisma.app.findUnique({ where: { slug: req.params.slug } });
      if (!row) {
        throw new AppError("not_found", `app "${req.params.slug}" not found`);
      }
      // A *relative* change, so the append runs against the origins read inside
      // the transaction rather than a pre-image this route read earlier. That is
      // about classifying against committed state — an origin already granted
      // concurrently is then correctly no delta at all. It is not protecting the
      // live blob: every added origin is elevated (packages/shared/src/approval.ts),
      // so the append never becomes a baseline delta and nothing here is written.
      return applyCapabilityChange(app.prisma, {
        appId: row.id,
        mutate: (effective) => ({
          ...effective,
          externalOrigins: [...effective.externalOrigins, origin],
        }),
        actor: actor.sub,
        actorOid: actor.oid,
        reason,
      });
    },
  );

  // Change how an app gates access (architecture §4.2). Reducing exposure
  // (→ internal/group) commits immediately; going **public** is elevated and
  // opens an approval request (docs/design/approvals.md §3, §6.3). Enabling
  // `password` visibility is NOT done here — it needs a minted credential, so
  // it keeps its dedicated /access/password routes below.
  app.post<{ Params: { slug: string } }>(
    "/api/v1/apps/:slug/visibility",
    { preHandler: [authenticate, ownsApp] },
    async (req): Promise<VisibilityUpdateResult> => {
      const { visibility, reason } = SetVisibilityRequestSchema.parse(req.body);
      const actor = requireActor(req);
      if (visibility.mode === "password") {
        throw new AppError(
          "conflict",
          "enable password access via POST /api/v1/apps/:slug/access/password (it mints the credential)",
        );
      }
      /**
       * Resolve group names for the audit record before opening the transaction,
       * so a Graph call cannot hold a database connection. These names record what
       * the operator selected at the time; they are not an authorization cache.
       * Lookup is best-effort: missing names must not fail the visibility write.
       */
      const groupNames = await resolveGroupNamesForAudit(visibilityGroupIds(visibility));

      return app.prisma.$transaction(async (tx): Promise<VisibilityUpdateResult> => {
        // Read inside the transaction. Two things downstream depend on the current
        // visibility: `classifyVisibilityChange` decides elevated-vs-baseline from
        // it, and the elevated branch stores it in `baseSnapshot` for the later
        // approve to compare against. Off a read taken before the transaction, both
        // can be deciding from a value that has already moved — and a wrong
        // `baseSnapshot` is worse than a stale read, because it is persisted and
        // silently defeats the approve-time conflict check.
        const row = await tx.app.findUnique({ where: { slug: req.params.slug } });
        if (!row) {
          throw new AppError("not_found", `app "${req.params.slug}" not found`);
        }

        // Both halves of the current value, and both halves of the requested one:
        // a `group → group` edit that moves only the group set is a real change,
        // and comparing modes alone reported it as a no-op (ADR-0040 §5).
        const before = { mode: row.visibilityMode, groupIds: row.visibilityGroupIds };
        // `after` is derived from the COLUMNS, not from the request body, so the
        // delta and the row it describes cannot disagree. Reading the body here
        // instead meant a request carrying `["eng","eng","prod"]` stored the
        // deduped set but audited `group:eng,eng,prod` — a diff describing a value
        // that was never written.
        const columns = visibilityToColumns(visibility);
        const after = { mode: columns.visibilityMode, groupIds: columns.visibilityGroupIds };
        const change = classifyVisibilityChange(before, after);
        if (!change) {
          return { app: toApp(row), applied: [], pending: null }; // no-op
        }

        if (change.elevated) {
          // The only elevated change is → public. When public is disabled we
          // refuse outright rather than opening an approval that could never be
          // safely committed. Reductions (→ internal/group) fall through below, so
          // an already-public app can always be migrated down.
          if (!publicAppsAllowed()) {
            throw new AppError("forbidden", "public apps are disabled on this deployment");
          }
          const baseSnapshot = captureSnapshot(
            capabilitiesFromRow(row),
            before,
            touchedAreas([change.delta]),
          );
          // No policy write here, so nothing to CAS: the request only records what
          // was asked for. A mode that moves while the request sits pending is
          // exactly what `baseSnapshot` exists to catch at approve time (§5).
          const pending = await createApprovalRequest(tx, {
            appId: row.id,
            deltas: [change.delta],
            risk: change.risk,
            baseSnapshot,
            requestedOid: actor.oid,
            requestedBy: actor.sub,
            reason,
          });
          return { app: toApp(row), applied: [], pending };
        }

        // Baseline reduction — apply now.
        const updated = await casPolicyWrite(tx, row, columns);
        await tx.auditEvent.create({
          data: {
            appId: row.id,
            actor: actor.sub,
            action: "app.visibility.set",
            // `groupIds` alongside the delta looks redundant — the delta's `to`
            // already encodes them as `group:a,b` — and is not: the delta is a
            // rendered diff, this is the machine-readable set, and an audit row is
            // the one place group values are recorded at all (ADR-0040 §7 keeps
            // names off the `apps` row precisely so there is a single live truth).
            metadata: {
              applied: [change.delta],
              groupIds: columns.visibilityGroupIds,
              // Omitted rather than nulled when nothing resolved — an absent key
              // reads as "we could not name these", a null reads as "these have
              // no names", and only the first is ever true.
              ...(Object.keys(groupNames).length > 0 ? { groupNames } : {}),
            } as unknown as Prisma.InputJsonValue,
          },
        });
        return { app: toApp(updated), applied: [change.delta], pending: null };
      });
    },
  );

  /* --------------------------------------------------------------------- *
   * Shared-password access (`password` visibility) — the cleartext credential
   * an owner shares out-of-band for external demos (docs/features/
   * authentication.md). All four routes are authenticated, including the GET:
   * the password never appears in `toApp`/`toManifest` or any open read.
   * --------------------------------------------------------------------- */

  const credential = (slug: string, password: string, setAt: Date) =>
    PasswordCredentialResponseSchema.parse({
      password,
      url: appPublicUrl(slug),
      setAt: setAt.toISOString(),
    });

  // Enable password access: flip visibility to `password` and mint a passphrase
  // if there isn't one. Idempotent — re-enabling returns the existing credential
  // rather than rotating it out from under a URL already handed out.
  app.post<{ Params: { slug: string } }>(
    "/api/v1/apps/:slug/access/password",
    { preHandler: [authenticate, ownsApp] },
    async (req, reply) => {
      const actor = requireActor(req);
      // Operator policy: enabling a password app is a move into an open surface;
      // refuse when disabled. Disabling (DELETE, reverts to internal) stays open
      // so an owner can always migrate an existing password app away.
      if (!passwordAppsAllowed()) {
        throw new AppError("forbidden", "password apps are disabled on this deployment");
      }
      // Answer the idempotent re-enable without minting. `hashPassword` costs a
      // ~128 MiB scrypt derivation (packages/shared/src/scrypt.ts calls that an
      // exhaustion amplifier, which is why the *edge* caps concurrency; the portal
      // does not), so paying it to hand back a credential that already exists puts
      // a real memory cost behind an authenticated one-liner. This read is a fast
      // path only — the authoritative check is the one inside the transaction.
      const existing = await app.prisma.app.findUnique({ where: { slug: req.params.slug } });
      if (!existing) {
        throw new AppError("not_found", `app "${req.params.slug}" not found`);
      }
      if (
        existing.visibilityMode === "password" &&
        existing.passwordEnc &&
        existing.passwordSetAt
      ) {
        return credential(
          existing.slug,
          decryptPassword(existing.passwordEnc),
          existing.passwordSetAt,
        );
      }

      // Mint before opening the transaction: holding a transaction (and its
      // connection) open across the KDF would idle a pool slot for the whole run.
      const password = generatePassphrase();
      const setAt = new Date();
      const { hash, salt } = await hashPassword(password);

      const minted = await app.prisma.$transaction(async (tx) => {
        const row = await tx.app.findUnique({ where: { slug: req.params.slug } });
        if (!row) {
          throw new AppError("not_found", `app "${req.params.slug}" not found`);
        }
        if (row.visibilityMode === "password" && row.passwordEnc && row.passwordSetAt) {
          return {
            fresh: false,
            cred: credential(row.slug, decryptPassword(row.passwordEnc), row.passwordSetAt),
          };
        }
        // CAS: the idempotency check above is a read-then-act on `visibilityMode`.
        // Two concurrent enables would both pass it, both mint, and both write —
        // and the loser would be handed a cleartext passphrase that is *not* the
        // one stored, so the URL they were given does not work and the passphrase
        // that does is unrecoverable. The loser now gets a 409 instead.
        await casPolicyWrite(
          tx,
          row,
          {
            visibilityMode: "password",
            visibilityGroupIds: [],
            passwordHash: hash,
            passwordSalt: salt,
            passwordEnc: encryptPassword(password),
            passwordSetAt: setAt,
          },
          "this app's access mode changed while password access was being enabled — re-read it and retry",
        );
        await tx.auditEvent.create({
          data: {
            appId: row.id,
            actor: actor.sub,
            action: "app.access.password.enable",
            metadata: {},
          },
        });
        return { fresh: true, cred: credential(row.slug, password, setAt) };
      });
      if (minted.fresh) reply.status(201);
      return minted.cred;
    },
  );

  // Rotate: reroll a fresh passphrase (no body) or set a manual one (`password`,
  // ≥12 chars). Requires password access to already be enabled.
  app.post<{ Params: { slug: string } }>(
    "/api/v1/apps/:slug/access/password/rotate",
    { preHandler: [authenticate, ownsApp] },
    async (req) => {
      const { password: manual } = SetPasswordRequestSchema.parse(req.body ?? {});
      const actor = requireActor(req);
      // Rotating keeps the app a password app — refuse when disabled (only the
      // DELETE migration-away path stays open).
      if (!passwordAppsAllowed()) {
        throw new AppError("forbidden", "password apps are disabled on this deployment");
      }
      // Hashed before the transaction for the same reason as enable, above.
      const password = manual ?? generatePassphrase();
      const setAt = new Date();
      const { hash, salt } = await hashPassword(password);

      return app.prisma.$transaction(async (tx) => {
        const row = await tx.app.findUnique({ where: { slug: req.params.slug } });
        if (!row) {
          throw new AppError("not_found", `app "${req.params.slug}" not found`);
        }
        if (row.visibilityMode !== "password") {
          throw new AppError("conflict", "password access is not enabled for this app");
        }
        // Writes only the credential columns, but the guard above reads a policy
        // column — so it CASes too. Otherwise a concurrent disable landing between
        // the guard and the write re-populates credentials on an app that is no
        // longer a password app, and the edge projects those columns.
        await casPolicyWrite(
          tx,
          row,
          {
            passwordHash: hash,
            passwordSalt: salt,
            passwordEnc: encryptPassword(password),
            passwordSetAt: setAt,
          },
          "this app's access mode changed while the password was being rotated — re-read it and retry",
        );
        await tx.auditEvent.create({
          data: {
            appId: row.id,
            actor: actor.sub,
            action: "app.access.password.rotate",
            metadata: { manual: manual !== undefined },
          },
        });
        return credential(row.slug, password, setAt);
      });
    },
  );

  // Re-display the current credential. Authenticated read — never an open route.
  app.get<{ Params: { slug: string } }>(
    "/api/v1/apps/:slug/access/password",
    { preHandler: [authenticate, ownsApp] },
    async (req) => {
      const row = await app.prisma.app.findUnique({ where: { slug: req.params.slug } });
      if (!row) {
        throw new AppError("not_found", `app "${req.params.slug}" not found`);
      }
      if (row.visibilityMode !== "password" || !row.passwordEnc || !row.passwordSetAt) {
        throw new AppError("not_found", "password access is not enabled for this app");
      }
      return credential(row.slug, decryptPassword(row.passwordEnc), row.passwordSetAt);
    },
  );

  // Disable password access: revert to internal and wipe the credential. Mutating,
  // idempotent — a non-password app is already in the desired state.
  app.delete<{ Params: { slug: string } }>(
    "/api/v1/apps/:slug/access/password",
    { preHandler: [authenticate, ownsApp] },
    async (req, reply) => {
      const actor = requireActor(req);
      await app.prisma.$transaction(async (tx) => {
        const row = await tx.app.findUnique({ where: { slug: req.params.slug } });
        if (!row) {
          throw new AppError("not_found", `app "${req.params.slug}" not found`);
        }
        if (row.visibilityMode !== "password") return; // already in the desired state
        await casPolicyWrite(
          tx,
          row,
          {
            // Back to the baseline, deliberately: disabling a shared password
            // must not tighten the app past where it started, or turning off a
            // demo credential would silently lock out everyone who had access.
            visibilityMode: "internal",
            passwordHash: null,
            passwordSalt: null,
            passwordEnc: null,
            passwordSetAt: null,
          },
          "this app's access mode changed while password access was being disabled — re-read it and retry",
        );
        await tx.auditEvent.create({
          data: {
            appId: row.id,
            actor: actor.sub,
            action: "app.access.password.disable",
            metadata: {},
          },
        });
      });
      reply.status(204).send();
    },
  );
}
