/**
 * CSP for every app response (architecture §4.4, ADR-0009). Approved
 * externalOrigins extend connect-src/img-src; report-uri sends violations to
 * the edge. Apply it to all asset types because SVG, XHTML, and XML can execute
 * scripts too.
 *
 * Apps are untrusted. Restrict connections to approved destinations, forms to
 * self, framing to none, and base URLs to self. form-action must be explicit;
 * it does not inherit default-src. Inline scripts/styles, eval, wasm, and
 * curated CDNs are allowed for generated-app compatibility. Open HTTPS images
 * and navigation remain possible data-exfiltration channels on the enforced
 * header; a tightened policy is measured in Report-Only first. object-src is
 * absent on the enforced policy (browsers fall back to default-src) until
 * enforcement lands.
 *
 * Keep unsafe-inline: the fetch shim and offline registration are inlined so
 * they work on offline startup, and apps may have their own inline scripts.
 * Adding a script hash or nonce makes CSP3 browsers ignore unsafe-inline.
 *
 * worker-src self/blob permits dedicated and shared workers. Service workers
 * require HTTP(S) URLs; they cannot register from blob URLs. The asset handler
 * rejects app-supplied service workers because a root-scoped worker could read
 * the auth handoff URL. The offline worker is platform-owned and scope-limited
 * (ADR-0035). This CSP also governs that worker's own fetch requests.
 */
import type { FastifyReply } from "fastify";
import type { EdgeConfig } from "../config.js";

const CDN_ALLOWLIST = [
  "https://cdnjs.cloudflare.com",
  "https://cdn.jsdelivr.net",
  "https://unpkg.com",
  "https://esm.sh",
  "https://cdn.tailwindcss.com",
];
const CDNS = CDN_ALLOWLIST.join(" ");

/** Same-origin path the edge accepts CSP violation reports on (serving/cspReport.ts). */
export const CSP_REPORT_PATH = "/_csp-report";

export const CSP_REPORT_ONLY_HEADER = "content-security-policy-report-only";

/**
 * Reduce approved external origins to bare CSP sources (scheme+host+port). They
 * arrive as validated URLs; `new URL().origin` strips any path so a stored
 * `https://api.foo.com/v1` doesn't become a path-restricted source. Invalid
 * entries are dropped (fail-closed — never widen on garbage).
 */
function originSources(origins: readonly string[]): string[] {
  const out: string[] = [];
  for (const o of origins) {
    try {
      const origin = new URL(o).origin;
      if (origin !== "null" && !out.includes(origin)) out.push(origin);
    } catch {
      // skip
    }
  }
  return out;
}

interface PolicyOptions {
  externalOrigins: readonly string[];
  /** false: today's enforced img-src. true: the tightened policy (Report-Only). */
  tight: boolean;
  imgSrcExtra: readonly string[];
}

function buildPolicy(o: PolicyOptions): string {
  const extra = originSources(o.externalOrigins);
  const suffix = extra.length ? ` ${extra.join(" ")}` : "";
  const imgOrigins = originSources([...o.externalOrigins, ...o.imgSrcExtra]);
  const imgSuffix = imgOrigins.length ? ` ${imgOrigins.join(" ")}` : "";
  return [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' ${CDNS}`,
    `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com ${CDNS}`,
    `font-src 'self' data: https://fonts.gstatic.com ${CDNS}`,
    o.tight ? `img-src 'self' data: blob:${imgSuffix}` : `img-src https: data: blob:${suffix}`,
    "media-src 'self' data: blob:",
    ...(o.tight ? ["object-src 'none'"] : []),
    `connect-src 'self'${suffix}`,
    "worker-src 'self' blob:",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    `report-uri ${CSP_REPORT_PATH}`,
  ].join("; ");
}

/**
 * Build an app's enforced CSP. With no approved origins this is the static
 * baseline (the strict data-flow directives are the containment — see the
 * module doc). Each approved origin widens `connect-src` (the meaningful grant;
 * `img-src` already permits any https) and `img-src`.
 */
export function buildAppCsp(externalOrigins: readonly string[] = []): string {
  return buildPolicy({ externalOrigins, tight: false, imgSrcExtra: [] });
}

export function buildAppCspReportOnly(
  externalOrigins: readonly string[] = [],
  imgSrcExtra: readonly string[] = [],
): string {
  return buildPolicy({ externalOrigins, tight: true, imgSrcExtra });
}

/** Set the enforced policy and, during the measurement phase, the Report-Only one. */
export function applyAppCsp(
  reply: FastifyReply,
  externalOrigins: readonly string[],
  config: Pick<EdgeConfig, "imgSrcExtra">,
): void {
  reply.header("content-security-policy", buildAppCsp(externalOrigins));
  reply.header(CSP_REPORT_ONLY_HEADER, buildAppCspReportOnly(externalOrigins, config.imgSrcExtra));
}

/** The baseline CSP (no per-app origins). */
export const APP_CSP = buildAppCsp();
