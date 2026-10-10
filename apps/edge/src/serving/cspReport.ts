import { type Pool } from "pg";
import type { FastifyReply, FastifyRequest } from "fastify";
import {
  ATTR_APP_ID,
  ATTR_CSP_DIRECTIVE,
  ATTR_CSP_DISPOSITION,
  ATTR_OUTCOME,
  CSP_REPORT_DIRECTIVES,
  type CspReportDirective,
  type CspReportDisposition,
  type CspReportOutcome,
} from "@azx-pbc/shared/telemetry";
import type { CspReportInsertThrottle } from "./cspReportThrottle.js";
import { createEdgePool, type EdgePoolOpts } from "../db/pool.js";
import type { RegistryReader } from "../registry/projection.js";
import { sendNotFound } from "../errors.js";
import { instruments } from "../telemetry.js";

/**
 * CSP-violation report sink (docs/design/approvals.md §6.2). The app's CSP
 * `report-uri` points at the same-origin `/_csp-report`; the browser POSTs a
 * violation, and the edge appends one row. Like the metering ledger this is a
 * narrow, deliberate widening of the edge's read-only posture: INSERT only, no
 * SELECT — a compromised edge can append reports but never enumerate them (the
 * grant is the boundary). The portal reads them for the Violations screen.
 */

export interface CspReportRecord {
  appId: string;
  directive: string;
  blockedUri: string;
  documentUri: string | null;
}

export interface CspReportStore {
  record(report: CspReportRecord): Promise<void>;
  close(): Promise<void>;
}

export class PgCspReportStore implements CspReportStore {
  #pool: Pool;

  constructor(databaseUrl: string, opts: EdgePoolOpts = {}) {
    // Spread, don't re-list — see the note in auth/sessions.ts.
    this.#pool = createEdgePool(databaseUrl, {
      ...opts,
      max: opts.max ?? 4,
      label: opts.label ?? "csp-reports",
    });
  }

  async record(report: CspReportRecord): Promise<void> {
    await this.#pool.query(
      // gen_random_uuid() server-side (Prisma's @default(uuid()) is client-side).
      `INSERT INTO csp_reports (id, "appId", directive, "blockedUri", "documentUri")
       VALUES (gen_random_uuid(), $1, $2, $3, $4)`,
      [report.appId, report.directive, report.blockedUri, report.documentUri],
    );
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }
}

/** Cap stored strings — a violation URL can be arbitrarily long. */
function clamp(v: unknown, max = 2048): string {
  return typeof v === "string" ? v.slice(0, max) : "";
}

function foldDisposition(raw: unknown): CspReportDisposition {
  if (raw === "enforce" || raw === "report") return raw;
  return "unknown";
}

/**
 * Pull the violated directive + blocked URL out of either report shape: the
 * legacy `report-uri` body (`{ "csp-report": {...} }`) or the Reporting-API
 * `report-to` body (an array of `{ type, body }`). Returns null if neither
 * yields a blocked URL (nothing worth storing).
 */
export function extractReport(body: unknown): {
  directive: string;
  blockedUri: string;
  documentUri: string | null;
  disposition: CspReportDisposition;
} | null {
  // Reporting-API: array of reports.
  if (Array.isArray(body)) {
    const r = body.find(
      (x) =>
        typeof x === "object" && x !== null && (x as { type?: string }).type === "csp-violation",
    ) as { body?: Record<string, unknown> } | undefined;
    const b = r?.body;
    if (b) {
      const blockedUri = clamp(b.blockedURL ?? b["blocked-uri"]);
      if (!blockedUri) return null;
      return {
        directive: clamp(b.effectiveDirective ?? b.violatedDirective, 128) || "unknown",
        blockedUri,
        documentUri: clamp(b.documentURL) || null,
        disposition: foldDisposition(b.disposition),
      };
    }
    return null;
  }
  // Legacy report-uri: { "csp-report": {...} }.
  if (typeof body === "object" && body !== null) {
    const b = (body as Record<string, unknown>)["csp-report"];
    if (typeof b === "object" && b !== null) {
      const o = b as Record<string, unknown>;
      const blockedUri = clamp(o["blocked-uri"]);
      if (!blockedUri) return null;
      return {
        directive: clamp(o["effective-directive"] ?? o["violated-directive"], 128) || "unknown",
        blockedUri,
        documentUri: clamp(o["document-uri"]) || null,
        disposition: foldDisposition(o["disposition"]),
      };
    }
  }
  return null;
}

/** Fold a raw violated-directive string to the bounded metric dimension set. */
export function foldDirective(raw: string): CspReportDirective {
  const token = raw.trim().toLowerCase().split(/\s+/)[0] ?? "";
  if ((CSP_REPORT_DIRECTIVES as readonly string[]).includes(token)) {
    return token as CspReportDirective;
  }
  if (token === "script-src-elem" || token === "script-src-attr") return "script-src";
  if (token === "style-src-elem" || token === "style-src-attr") return "style-src";
  return "other";
}

export interface CspReportRuntime {
  registry: RegistryReader;
  /** null = accept-and-drop (no DB writer wired). */
  store: CspReportStore | null;
  /** null ⇒ uncapped (tests). */
  insertThrottle: CspReportInsertThrottle | null;
}

/**
 * Handler for `POST /_csp-report` on app hosts. Resolves the app, records the
 * violation if there's a store, and always answers 204 — the browser ignores
 * the body, and a malformed/empty report must never error loudly.
 */
export function makeCspReportHandler(rt: CspReportRuntime) {
  return async function handle(
    req: FastifyRequest,
    reply: FastifyReply,
    slug: string,
  ): Promise<void> {
    const entry = rt.registry.getApp(slug);
    if (!entry) {
      sendNotFound(reply);
      return;
    }
    const parsed = extractReport(req.body);
    if (parsed) {
      const { disposition, ...record } = parsed;
      const decision = rt.insertThrottle
        ? await rt.insertThrottle.admit(entry.appId)
        : { insert: true as const };
      let outcome: CspReportOutcome = "dropped";
      if (rt.store && decision.insert) {
        try {
          await rt.store.record({ appId: entry.appId, ...record });
          outcome = "recorded";
        } catch (err) {
          outcome = "failed";
          req.log.warn({ err }, "failed to record CSP report");
        }
      } else if (!rt.store || decision.insert) {
        outcome = "recorded";
      }
      instruments().cspReports.add(1, {
        [ATTR_APP_ID]: entry.appId,
        [ATTR_CSP_DIRECTIVE]: foldDirective(record.directive),
        [ATTR_CSP_DISPOSITION]: disposition,
        [ATTR_OUTCOME]: outcome,
      });
    }
    reply.status(204).send();
  };
}
