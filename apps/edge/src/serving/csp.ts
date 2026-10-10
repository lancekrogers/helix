/**
 * CSP for every app response (architecture §4.4, ADR-0009). Approved
 * externalOrigins extend connect-src/img-src; report-uri sends violations to
 * the edge. Apply it to all asset types because SVG, XHTML, and XML can execute
 * scripts too.
 *
 * Apps are untrusted. Restrict connections to approved destinations, forms to
 * self, framing to none, and base URLs to self. form-action must be explicit;
 * it does not inherit default-src. Inline scripts/styles, eval, wasm, and
 * curated CDNs are allowed for generated-app compatibility. By default `img-src`
 * is `'self' data: blob:` plus approved origins and operator `EDGE_IMG_SRC_EXTRA`,
 * with `object-src 'none'`. Top-level navigation, popups/`window.open`, approved
 * origins, request URLs to permitted CDN hosts (Hypothesis), WebRTC, and DNS
 * prefetch/preconnect hints remain open channels; the platform does not deliver
 * confidentiality against a hostile app author.
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

/** Hostnames safe to embed in a CSP source list (LDH labels, IPv4, or IPv6). */
export function isCspSafeHostname(hostname: string): boolean {
  if (hostname.includes(":")) {
    return /^[0-9a-f:.]+$/i.test(hostname);
  }
  return /^[a-z0-9.-]+$/.test(hostname);
}

function originSources(origins: readonly string[], schemes: readonly string[]): string[] {
  const out: string[] = [];
  for (const o of origins) {
    try {
      const parsed = new URL(o);
      if (!schemes.includes(parsed.protocol)) continue;
      if (parsed.hostname.includes("*")) continue;
      if (!isCspSafeHostname(parsed.hostname)) continue;
      const origin = parsed.origin;
      if (origin !== "null" && !out.includes(origin)) out.push(origin);
    } catch {
      // skip
    }
  }
  return out;
}

function connectOriginSources(origins: readonly string[]): string[] {
  return originSources(origins, ["https:", "wss:"]);
}

function imgOriginSources(origins: readonly string[]): string[] {
  return originSources(origins, ["https:"]);
}

export interface AppCspOptions {
  /** Operator-trusted image origins (EDGE_IMG_SRC_EXTRA). */
  imgSrcExtra?: readonly string[];
  /** EDGE_IMG_SRC_ALLOW_ALL: restore `https:` in img-src. */
  imgSrcAllowAll?: boolean;
}

type ImgMode = "tight" | "permissive" | "legacy";

interface PolicyOptions {
  externalOrigins: readonly string[];
  imgSrcExtra: readonly string[];
  imgMode: ImgMode;
  objectSrcNone: boolean;
}

function buildPolicy(o: PolicyOptions): string {
  const connectSources = connectOriginSources(o.externalOrigins);
  const connectSuffix = connectSources.length ? ` ${connectSources.join(" ")}` : "";
  const imgSources =
    o.imgMode === "legacy"
      ? imgOriginSources(o.externalOrigins)
      : imgOriginSources([...o.externalOrigins, ...o.imgSrcExtra]);
  const imgSuffix = imgSources.length ? ` ${imgSources.join(" ")}` : "";
  const img =
    o.imgMode === "tight"
      ? `img-src 'self' data: blob:${imgSuffix}`
      : `img-src https: data: blob:${imgSuffix}`;
  return [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' ${CDNS}`,
    `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com ${CDNS}`,
    `font-src 'self' data: https://fonts.gstatic.com ${CDNS}`,
    img,
    "media-src 'self' data: blob:",
    ...(o.objectSrcNone ? ["object-src 'none'"] : []),
    `connect-src 'self'${connectSuffix}`,
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
 * module doc). Each approved origin widens `connect-src` and `img-src`.
 */
export function buildAppCsp(
  externalOrigins: readonly string[] = [],
  opts: AppCspOptions = {},
): string {
  return buildPolicy({
    externalOrigins,
    imgSrcExtra: opts.imgSrcExtra ?? [],
    imgMode: opts.imgSrcAllowAll ? "permissive" : "tight",
    objectSrcNone: true,
  });
}

/** The policy enforced before img-src was tightened (measurement mode): open `img-src`, no `object-src`. */
export function buildLegacyEnforcedAppCsp(externalOrigins: readonly string[] = []): string {
  return buildPolicy({
    externalOrigins,
    imgSrcExtra: [],
    imgMode: "legacy",
    objectSrcNone: false,
  });
}

/** Tight policy for the Report-Only header during the measurement window. */
export function buildMeasurementReportOnlyCsp(
  externalOrigins: readonly string[] = [],
  imgSrcExtra: readonly string[] = [],
): string {
  return buildPolicy({
    externalOrigins,
    imgSrcExtra,
    imgMode: "tight",
    objectSrcNone: true,
  });
}

/** Set the enforced CSP; during measurement, also the Report-Only tightened policy. */
export function applyAppCsp(
  reply: FastifyReply,
  externalOrigins: readonly string[],
  config: Pick<EdgeConfig, "imgSrcExtra" | "imgSrcAllowAll" | "imgSrcReportOnly">,
): void {
  if (config.imgSrcReportOnly) {
    reply.header("content-security-policy", buildLegacyEnforcedAppCsp(externalOrigins));
    reply.header(
      CSP_REPORT_ONLY_HEADER,
      buildMeasurementReportOnlyCsp(externalOrigins, config.imgSrcExtra),
    );
    return;
  }
  reply.header("content-security-policy", buildAppCsp(externalOrigins, config));
}

/** The baseline CSP (no per-app origins). */
export const APP_CSP = buildAppCsp();
