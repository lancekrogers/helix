import type { Delta } from "./approval.js";
import { parseFetchOriginKey } from "./approval.js";

/**
 * Approver-facing plain-English capability explanations, keyed to the delta
 * path vocabulary the classifier emits (`packages/shared/src/approval.ts`).
 * The approval queue renders one chip per delta with a help tooltip built
 * from this record; the copy is written for the person deciding the request,
 * not the app author (the editor-side copy lives in the portal SPA).
 *
 * This module is deliberately pure data + one resolver so it is safe to import
 * from the browser SPA.
 */

export interface CapabilityHelp {
  /** Plain-English capability name, e.g. "MCP tool servers". */
  title: string;
  /** What the app can do once the grant lands. */
  grants: string;
  /** What could go wrong / why the capability is gated. Short bullets. */
  risks: string[];
  /** What drives this capability's risk rating, in one line. */
  riskWhy: string;
}

/** The unknown-path fallback — the tooltip still shows the raw path so an approver is never stuck. */
const FALLBACK: CapabilityHelp = {
  title: "Capability change",
  grants: "This request changes the app's capability manifest (see the change listed on the card).",
  risks: [
    "No specific explanation is on file for this change — ask the app owner what it is for if unclear.",
  ],
  riskWhy: "Rated by the platform's classifier; treat an unexplained change with care.",
};

const ENTRIES: Record<string, CapabilityHelp> = {
  visibility: {
    title: "App visibility",
    grants:
      "Controls who can open the app: internal (any signed-in colleague), a named directory group, a shared password, or public (anyone on the internet, no sign-in).",
    risks: [
      "A public app is reachable by anonymous visitors anywhere — every page it serves is public from the moment this lands.",
      "A public app's visitors can never connect a vendor account (the platform blocks consent for them), so approving a connection grant alongside this is a likely broken promise.",
    ],
    riskWhy:
      "Going public crosses the tenant boundary — from directory members to everyone on the internet.",
  },

  mcp: {
    title: "MCP tool servers",
    grants:
      "Lets the app call tools on the named MCP server with the platform's identity — not as any individual user.",
    risks: [
      "An MCP server can change what its tools do at any time; approving this trusts the operator of that server indefinitely.",
      "Tool calls run server-side with platform credentials, so the blast radius is set by what the server offers, not by the app's page.",
    ],
    riskWhy:
      "Every MCP grant elevates: the platform's pre-approved allowlist is empty, so each server is trusted by hand, once, here.",
  },

  externalOrigins: {
    title: "Direct browser calls",
    grants:
      "Allows the app's own JavaScript — running in each visitor's browser — to call the named host directly, by widening the page's Content-Security-Policy.",
    risks: [
      "Requests leave the visitor's browser, so any credential the app attaches is visible to the page and to the destination host.",
      "The destination host sees your colleagues' IPs and browsers, not the platform's.",
    ],
    riskWhy: "A new browser-callable host is also a new place the page can send data.",
  },

  "llm.models": {
    title: "LLM models",
    grants:
      "Adds the named model to what the app may use through the platform's LLM gateway, which keys, meters and bills every call.",
    risks: [
      "A model outside the curated set has not been priced or vetted by the platform — its cost per call and behavior are less well known.",
    ],
    riskWhy: "Curated models are exactly the priced catalog; an unpriced model gets a human look.",
  },

  "llm.dollarsPerDay": {
    title: "LLM spend budget",
    grants:
      "Caps the app's daily LLM spend at the requested amount. Removing the cap falls back to the install default (often $50/day, unless the operator changed it).",
    risks: [
      "The cap is a ceiling, not a prediction — a runaway loop can burn up to it every day.",
      "Without a cap, spend is bounded only by that install default — which may be higher than $50/day or unlimited on some deployments.",
    ],
    riskWhy:
      "Removing a cap can raise the worst-case daily bill above what was approved; spend above the $50/day baseline also needs a human look.",
  },

  "data.user": {
    title: "Per-user storage",
    grants: "Gives each signed-in user of the app a small private store keyed to their account.",
    risks: [
      "The app reads and writes it on the user's behalf — whatever it stores is as visible as the app is.",
    ],
    riskWhy: "Routine: scoped to one user at a time, inside the app.",
  },

  "data.collections": {
    title: "App collections",
    grants: "Adds the named collection — a table of rows the app itself owns and manages.",
    risks: ["The app can hold whatever rows it likes in it, up to its storage budget."],
    riskWhy: "Routine: app-scoped data with no cross-user reach.",
  },

  "data.shared": {
    title: "Shared data keys",
    grants:
      "Lets the app read (and, for write keys, change) the named keys in the app's shared store — visible to everyone who can open the app.",
    risks: [
      "Anything in the shared store is readable app-wide; it can never deliver per-user privacy.",
    ],
    riskWhy: "Routine: the shared store is app-scoped and gated by the app's own visibility.",
  },

  "data.sharedPrefixes": {
    title: "Shared key prefixes",
    grants:
      "Authorizes every shared key under a prefix — one grant covers unboundedly many runtime-chosen keys, unlike the literal keys listed elsewhere on the card.",
    risks: [
      "A write prefix lets the app create new rows at runtime; the platform requires a daily write budget alongside it, so the grant and its bound are approved together.",
    ],
    riskWhy:
      "Flagged for human review because it is unbounded, but rated routine: the shared store is app-scoped and only reachable through the app's visibility gate.",
  },

  "data.budget": {
    title: "Data budgets",
    grants:
      "Caps the app's daily data writes or stored bytes. Removing a cap entirely means unlimited.",
    risks: ["An unset or large budget raises the worst-case storage and write abuse."],
    riskWhy: "Budgets above the platform baseline get a human look.",
  },

  "fetch.origins": {
    title: "Proxied origin",
    grants:
      "Lets the app call the named host through the platform's egress proxy — audited, metered and SSRF-checked.",
    risks: [
      "The call is made server-side by the platform, so it works even where a visitor's browser could not.",
    ],
    riskWhy: "A new outbound host is a server-side channel, but no credential travels with it.",
  },

  "fetch.origins.secret": {
    title: "Proxied origin + stored secret",
    grants:
      "Lets the app call the named host through the egress proxy with a stored secret injected server-side into each call — the app itself never sees the credential.",
    risks: [
      "Anyone who can open the app can spend that credential's quota — every proxied call carries it.",
      "A bug (or a malicious page) can make the platform use the secret against the host on any visitor's behalf.",
    ],
    riskWhy:
      "High: every proxied call will carry a real stored credential the app cannot read but can spend.",
  },

  "fetch.origins.provider": {
    title: "Delegated provider connection",
    grants:
      "Lets the app call the named provider as the signed-in user, once that user approves the connection — the platform injects the user's OAuth token server-side.",
    risks: [
      "After a user consents, the app can act as that user against the provider; approving the binding vouches for the configuration, not for each use.",
      "If the provider's configuration is edited later, the binding silently stops working until re-approved — stale grants fail closed.",
    ],
    riskWhy: "High: OAuth delegation that acts as your users, consent-gated per user.",
  },

  "fetch.ergonomics": {
    title: "Fetch ergonomics",
    grants:
      "Turns on a transparent rewrite of the app's fetch calls to the proxy, or the connect helper popup. It changes how calls are routed, not what the app may reach.",
    risks: [],
    riskWhy: "Ergonomics only — never a privilege grant.",
  },

  "fetch.budget": {
    title: "Proxy request budget",
    grants: "Caps the app's daily proxied requests. Removing the cap means unlimited.",
    risks: ["An unset or large budget raises the worst-case proxy abuse."],
    riskWhy: "Budgets above the platform baseline get a human look.",
  },

  offline: {
    title: "Offline access (service worker)",
    grants:
      "Lets the app register a service worker that caches and serves its own pages under the given path prefix while the device is offline.",
    risks: [
      "A cached shell can keep rendering after a user loses access; revocation catches up on the device's next online load.",
      "Scopes must stay narrow — root-scoped workers are refused platform-wide because they could see authentication handoffs.",
    ],
    riskWhy:
      "Medium, not high: the exposure is stale rendering after deauthorization — the browser's storage already persists without any grant.",
  },
};

/**
 * The help entry for one delta. Fetch-origin adds resolve by their credential
 * variant (keyless / secret-bound / provider-bound) because the three carry
 * materially different risk; any other path resolves by policy area.
 */
export function deltaHelp(d: Delta): CapabilityHelp {
  const path = d.path;

  if (path === "visibility") return ENTRIES.visibility!;
  if (path === "offline.scope") return ENTRIES.offline!;
  if (path === "llm.dollarsPerDay") return ENTRIES["llm.dollarsPerDay"]!;
  if (path === "data.writesPerDay" || path === "data.bytesPerDay") return ENTRIES["data.budget"]!;
  if (path === "fetch.shim" || path === "shim.connect") return ENTRIES["fetch.ergonomics"]!;
  if (path === "fetch.requestsPerDay") return ENTRIES["fetch.budget"]!;
  if (path === "data.user") return ENTRIES["data.user"]!;
  if (path.startsWith("data.collections")) return ENTRIES["data.collections"]!;
  if (path.startsWith("data.sharedReadPrefixes") || path.startsWith("data.sharedWritePrefixes"))
    return ENTRIES["data.sharedPrefixes"]!;
  if (path.startsWith("data.sharedRead") || path.startsWith("data.sharedWrite"))
    return ENTRIES["data.shared"]!;
  if (path.startsWith("llm.models")) return ENTRIES["llm.models"]!;

  // `fetch.origins[+<key>]` — the key form is fetchOriginKey's (approval.ts),
  // so the credential variant is recoverable from the path alone.
  const fetchAdd = /^fetch\.origins\[[+-](.+)\]$/.exec(path);
  if (fetchAdd) {
    const bound = parseFetchOriginKey(fetchAdd[1]!);
    if (bound.provider !== undefined) return ENTRIES["fetch.origins.provider"]!;
    if (bound.connection !== undefined) return ENTRIES["fetch.origins.secret"]!;
    return ENTRIES["fetch.origins"]!;
  }

  if (path.startsWith("mcp")) return ENTRIES.mcp!;
  if (path.startsWith("externalOrigins")) return ENTRIES.externalOrigins!;

  return FALLBACK;
}
