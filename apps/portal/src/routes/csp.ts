import type { FastifyInstance } from "fastify";
import { CspViolationsPageSchema } from "@azx-pbc/shared";
import { authenticate, requireAdmin } from "../plugins/auth.js";
import { toCspViolation, type CspViolationRow } from "../db/mappers.js";

/** Violations older than this are omitted from the admin aggregate. */
export const CSP_VIOLATIONS_LOOKBACK_DAYS = 30;

/**
 * Read-side over the `csp_reports` sink (docs/design/approvals.md §6.2). The
 * **edge writes** the reports (INSERT-only); this endpoint aggregates them for
 * the admin Violations screen, which turns each blocked origin into a one-click
 * origin-grant approval request (`POST /api/v1/apps/:slug/access/origin`).
 */
export async function cspRoutes(app: FastifyInstance): Promise<void> {
  app.get("/api/v1/csp/violations", { preHandler: authenticate }, async (req) => {
    requireAdmin(req);
    const rows = await app.prisma.$queryRaw<CspViolationRow[]>`
      SELECT r."appId", a.slug AS slug, a.capabilities AS capabilities,
             r.directive, r."blockedUri",
             COUNT(*)::int AS count, MAX(r."createdAt") AS "lastSeen"
      FROM csp_reports r
      LEFT JOIN apps a ON a.id = r."appId"
      WHERE r."createdAt" >= NOW() - (${CSP_VIOLATIONS_LOOKBACK_DAYS} * INTERVAL '1 day')
      GROUP BY r."appId", a.slug, a.capabilities, r.directive, r."blockedUri"
      ORDER BY MAX(r."createdAt") DESC
      LIMIT 200`;
    return CspViolationsPageSchema.parse({ violations: rows.map(toCspViolation) });
  });
}
