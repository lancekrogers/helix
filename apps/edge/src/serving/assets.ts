import { extname } from "node:path";
import type { Readable } from "node:stream";
import type { FastifyReply, FastifyRequest } from "fastify";
import { controlOrigin, publicOrigin, type EdgeConfig } from "../config.js";
import type { BlobReader, BlobGetResult } from "../blob/client.js";
import type { RegistryEntry, RegistryReader } from "../registry/projection.js";
import type { SessionGate } from "../auth/gate.js";
import { visibilityModeAllowed } from "../auth/validate.js";
import { sendForbidden, sendGone, sendNotFound, sendUnavailable } from "../errors.js";
import { normalizeRequestPath } from "./paths.js";
import { applyAppCsp } from "./csp.js";
import { buildShimScript, injectHeadScripts } from "./shim.js";
import { buildConnectScript } from "./connectHelper.js";
import { buildRegistrationSnippet } from "./serviceWorker.js";
import { isDocumentLoad, type VisitRecorder } from "./visits.js";

/**
 * The app-host request path (architecture §4.3): resolve slug → live version
 * → session gate → blob key, stream the asset. Single-page apps get `/` →
 * index.html plus an index.html fallback for HTML-accepting misses
 * (client-side routers). Assets are served only after the auth check — there
 * are no public blob endpoints.
 */
export interface AssetHandlerDeps {
  config: EdgeConfig;
  registry: RegistryReader;
  blob: BlobReader;
  /** The session gate; absent only when the auth stack isn't wired. */
  gate?: SessionGate | null;
  /** Records a visit for a served HTML document (ADR-0050); absent in most tests. */
  recordVisit?: VisitRecorder | null;
}

export function makeAssetHandler(deps: AssetHandlerDeps) {
  const { config, registry, blob, gate, recordVisit } = deps;

  return async function assetHandler(
    req: FastifyRequest,
    reply: FastifyReply,
    slug: string,
  ): Promise<void> {
    // App-supplied service workers are refused: a root-scoped worker sees every
    // same-origin navigation — including the one-time handoff token on
    // `/_auth/complete?token=…` — before the edge does, and could convert a
    // user's in-browser login into a durable headless session. Browsers send
    // `Service-Worker: script` on every registration fetch, so refusing it here
    // kills registration while ordinary web workers keep working.
    //
    // The offline capability (ADR-0035) is the one exception, and it does not
    // widen this check: the worker it registers is **platform code** served from
    // a reserved `/_helix/` route that never reaches this handler, confined to a
    // validated non-root scope. No app bytes are ever registrable.
    if (req.headers["service-worker"] !== undefined) {
      sendForbidden(reply);
      return;
    }

    if (!registry.isLoaded()) {
      sendUnavailable(reply, "Registry unavailable; try again shortly.");
      return;
    }

    const entry = registry.getApp(slug);
    if (!entry) {
      sendNotFound(reply);
      return;
    }
    if (entry.archived) {
      sendGone(reply);
      return;
    }
    // Unknown slug and known-but-nothing-live answer identically.
    if (!entry.blobPrefix) {
      sendNotFound(reply);
      return;
    }

    // Operator policy: `public`/`password` are open surfaces this deployment
    // may forbid (EDGE_ALLOW_*_APPS). A disallowed mode is refused outright —
    // even an app already set that way — 403, never served. The owner migrates
    // it down to internal/group in the portal to restore service.
    if (!visibilityModeAllowed(entry.visibilityMode, config)) {
      sendForbidden(reply);
      return;
    }

    // The session gate (architecture §4.2). The dev bypass narrows its M2
    // meaning to "skip the gate" — serving still requires the registry entry
    // above, and loadConfig refuses the flag in production. `public` apps
    // (app-data design §6) are served to everyone with no session and never
    // touch the gate; every other mode stays behind it.
    if (!config.allowUnauthenticated && entry.visibilityMode !== "public") {
      if (!gate) {
        sendUnavailable(
          reply,
          "App serving requires authentication. Configure EDGE_OIDC_* (or set EDGE_DEV_ALLOW_UNAUTHENTICATED=true for local dev).",
        );
        return;
      }
      const session = await gate(req, reply, entry);
      if (!session) return; // the gate already responded (302/401)
    }

    const path = normalizeRequestPath(req.raw.url ?? "/");
    if (path === null) {
      sendNotFound(reply);
      return;
    }

    const method = req.method === "HEAD" ? "HEAD" : "GET";
    const relPath = path === "/" ? "index.html" : path.slice(1);
    const ifNoneMatch = firstHeader(req.headers["if-none-match"]);

    // Serve-time HTML rewrites: the fetch-proxy shim (§3.2), the connect
    // helper's opt-in grant (only the manifest's
    // `shim.connect` injects it; a provider binding alone never does) and/or
    // the offline capability's service-worker registration (ADR-0035). Any one
    // means we rewrite the document, so force the full body for the doc we'll
    // inject into (a 304 would skip injection) and serve it without an etag
    // below. Only the GET of an HTML-ish path is affected; other assets keep
    // their conditional path. Grants compose.
    const wantsShim = method === "GET" && entry.fetch.shim;
    const wantsConnect = method === "GET" && entry.shim?.connect === true;
    const wantsRegistration = method === "GET" && entry.offline !== null;
    const wantsInjection = wantsShim || wantsConnect || wantsRegistration;
    const likelyHtml = relPath === "index.html" || (req.headers.accept ?? "").includes("text/html");
    const effectiveInm = wantsInjection && likelyHtml ? undefined : ifNoneMatch;

    let result = await getUnderPrefix(blob, entry.blobPrefix, relPath, {
      method,
      ifNoneMatch: effectiveInm,
    });

    // SPA fallback: an HTML-navigation miss serves the app shell so deep
    // links into client-side routes work. Asset misses stay hard 404s.
    //
    // Scope-aware for an offline app (ADR-0035 §10): such an app is served from
    // a prefix and its bundle has no *root* `index.html`, so falling back to the
    // bundle root would 404 every deep link. A miss under the granted scope
    // falls back to that scope's own shell instead.
    const shellPath = shellFor(entry, path);
    if (
      result.kind === "not-found" &&
      relPath !== shellPath &&
      (req.headers.accept ?? "").includes("text/html")
    ) {
      result = await getUnderPrefix(blob, entry.blobPrefix, shellPath, {
        method,
        ifNoneMatch: effectiveInm,
      });
    }

    if (result.kind === "not-found") {
      sendNotFound(reply);
      return;
    }

    const isHtml = (result.kind === "found" ? (result.contentType ?? "") : "").startsWith(
      "text/html",
    );
    // HTML revalidates every time so pointer flips are immediately visible;
    // other assets may be 5 minutes stale (`private`: app content becomes
    // authenticated in M3 and must never land in shared caches).
    const cacheControl = result.kind === "found" && !isHtml ? "private, max-age=300" : "no-cache";

    // A visit is a top-level document load that passed the gate, including a
    // revalidated one (304), since that is still the app opening. A 304 has no
    // content type, so judge it by the path: an HTML file, or an extensionless
    // client route that the SPA fallback answers with the shell.
    const documentServed =
      result.kind === "not-modified"
        ? relPath.endsWith(".html") || extname(relPath) === ""
        : isHtml;
    if (recordVisit && documentServed && isDocumentLoad(req)) recordVisit(req, entry.appId);

    if (result.kind === "not-modified") {
      reply.status(304).header("cache-control", "no-cache");
      applyAppCsp(reply, entry.externalOrigins, config);
      if (result.etag) reply.header("etag", result.etag);
      reply.send();
      return;
    }

    // Injection: buffer this one HTML doc, insert the platform `<script>` blocks,
    // and send it as a string. No etag/last-modified — the injected bytes differ
    // from the Blob's, so a conditional 304 must never short-circuit injection.
    // Bounded to opt-in HTML (small); every other asset keeps streaming.
    //
    // The snippets are built here rather than above so a non-HTML GET on an
    // opt-in app doesn't pay for them, and inlined rather than referenced —
    // `/_helix/*` is unprecachable, so a `<script src>` there is exactly what an
    // offline cold boot cannot load (see `injectHeadScripts`). Shim first: it
    // must patch `fetch` before anything else on the page runs. The connect
    // helper's receiver-verification origins are the app's own host (start-route
    // pages) plus the auth host (completion pages).
    if (wantsInjection && isHtml) {
      const scripts: string[] = [];
      if (wantsShim) scripts.push(buildShimScript([...entry.fetch.connections.keys()]));
      if (wantsConnect) {
        scripts.push(
          buildConnectScript({
            platformOrigins: [publicOrigin(config, slug), controlOrigin(config, "auth")],
          }),
        );
      }
      if (entry.offline) scripts.push(buildRegistrationSnippet(entry.offline.scope));
      const injected = injectHeadScripts(await streamToString(result.body), scripts);
      reply
        .status(200)
        .header("content-type", result.contentType ?? "text/html; charset=utf-8")
        .header("cache-control", "no-cache")
        .header("x-content-type-options", "nosniff")
        .header("content-length", Buffer.byteLength(injected));
      applyAppCsp(reply, entry.externalOrigins, config);
      await reply.send(injected);
      return;
    }

    reply
      .status(200)
      .header("content-type", result.contentType ?? "application/octet-stream")
      .header("cache-control", cacheControl)
      .header("x-content-type-options", "nosniff");
    // On EVERY response, not just HTML: any browser-active document type
    // (SVG, XML, …) can carry script, and CSP on inert assets is harmless.
    applyAppCsp(reply, entry.externalOrigins, config);
    if (result.contentLength) reply.header("content-length", result.contentLength);
    if (result.etag) reply.header("etag", result.etag);
    if (result.lastModified) reply.header("last-modified", result.lastModified);

    // No hand-rolled teardown here: Fastify's `sendStream` wires `eos(res)` and
    // destroys the payload itself if the client goes away mid-stream, so pulling
    // from Blob already stops. The listener that used to sit here keyed off
    // `req.raw` 'close' with a `req.raw.destroyed` guard that is always true
    // inside that listener — the same "close means disconnect" misreading that
    // broke the fetch-proxy for every body-bearing method.

    // Fastify pipes the stream — assets are never buffered (project plan §1).
    await reply.send(result.body);
  };
}

/**
 * The bundle-relative shell an HTML miss falls back to (ADR-0035 §10).
 *
 * Normally the bundle root's `index.html`. For an app holding the offline grant,
 * a miss *inside* its scope falls back to that scope's own shell instead —
 * because such an app is served from a prefix, its zip nests under that prefix
 * (URL path maps literally to blob key), and there is no root `index.html` to
 * find. A miss outside the scope keeps the root behaviour, so an app that also
 * ships a landing page at `/` is unaffected.
 */
function shellFor(entry: RegistryEntry, path: string): string {
  const scope = entry.offline?.scope;
  if (scope !== undefined && `${path}/`.startsWith(scope)) {
    return `${scope.slice(1)}index.html`;
  }
  return "index.html";
}

async function getUnderPrefix(
  blob: BlobReader,
  blobPrefix: string,
  relPath: string,
  opts: { method: "GET" | "HEAD"; ifNoneMatch?: string },
): Promise<BlobGetResult> {
  const key = `${blobPrefix}${relPath}`;
  // Bug trap, not input validation — normalizeRequestPath already rejected
  // traversal, so a violation here is a programming error. Detect an actual
  // `..` path segment, not the substring: `vendor..min.js` is a legal name.
  if (!key.startsWith(blobPrefix) || key.includes("/../") || key.endsWith("/..")) {
    throw new Error(`asset key escaped version prefix: ${key}`);
  }
  return blob.get(key, opts);
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/** Drain a Blob body to a string — only for the opt-in shim HTML rewrite. */
async function streamToString(stream: Readable): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
  }
  return Buffer.concat(chunks).toString("utf8");
}
