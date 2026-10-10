import { SLUG_PATTERN } from "@azx-pbc/shared";

/**
 * Host classification — the two-router discipline (architecture §3, decision
 * 12): every request is app-subdomain traffic, auth-service traffic, or other
 * platform traffic, keyed strictly by hostname; control-plane handlers are
 * never mounted on app hosts. In the single-domain layout `auth.<base>` is the
 * central OIDC callback host (architecture §4.2, Appendix A). In split layout
 * only `auth.<controlDomain>` is auth; `auth.<baseDomain>` is reserved and
 * classifies as platform so it never runs the handoff.
 */
export type HostClass =
  | { kind: "app"; slug: string }
  | { kind: "legacy-app"; slug: string }
  | { kind: "auth" }
  | { kind: "platform" };

/**
 * Subdomain labels that can never be apps — reserved for platform services
 * (architecture §4.2, Appendix A). Note: the portal does not yet reject these
 * at app creation; until it does, a colliding app simply never gets traffic.
 */
export const RESERVED_SUBDOMAINS = new Set(["auth", "portal", "api", "www"]);

/** Classify a raw Host header against the apps and control domains. */
export function classifyHost(
  hostHeader: string | undefined,
  baseDomain: string,
  controlDomain: string = baseDomain,
  legacyAppRedirect = false,
): HostClass {
  if (!hostHeader || hostHeader.includes("[")) {
    return { kind: "platform" }; // absent or IPv6 literal — never an app host
  }

  const colon = hostHeader.indexOf(":");
  const host = (colon === -1 ? hostHeader : hostHeader.slice(0, colon)).toLowerCase();

  const suffix = `.${baseDomain}`;
  if (host.endsWith(suffix)) {
    const label = host.slice(0, -suffix.length);
    // Legacy layout: the auth host shares the apps suffix (today's behavior).
    if (label === "auth" && controlDomain === baseDomain) {
      return { kind: "auth" };
    }
    // Split layout: `auth` under the apps suffix is reserved — platform, never auth.
    if (label.includes(".") || !SLUG_PATTERN.test(label) || RESERVED_SUBDOMAINS.has(label)) {
      return { kind: "platform" };
    }
    return { kind: "app", slug: label };
  }
  if (host === `auth.${controlDomain}`) {
    return { kind: "auth" };
  }
  const controlSuffix = `.${controlDomain}`;
  if (legacyAppRedirect && controlDomain !== baseDomain && host.endsWith(controlSuffix)) {
    const label = host.slice(0, -controlSuffix.length);
    if (
      !label.includes(".") &&
      SLUG_PATTERN.test(label) &&
      !RESERVED_SUBDOMAINS.has(label) &&
      label !== "dev-api"
    ) {
      return { kind: "legacy-app", slug: label };
    }
  }
  return { kind: "platform" };
}
