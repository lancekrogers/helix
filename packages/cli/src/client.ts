import { z } from "zod";
import {
  ApiErrorSchema,
  AppSchema,
  CreateAppResultSchema,
  AuthConfigResponseSchema,
  PortalMeResponseSchema,
  UploadVersionResponseSchema,
  VersionSchema,
  type App,
  type AuthConfigResponse,
  type PortalMeResponse,
  type UploadVersionResponse,
  type Version,
  type Visibility,
} from "@azx-pbc/shared";
import type { TokenProvider } from "./auth/session.js";

/** A CLI-level error carrying the portal's error code when available. */
export class CliError extends Error {
  readonly code?: string;
  constructor(message: string, code?: string) {
    super(message);
    this.name = "CliError";
    this.code = code;
  }
}

export interface CreateAppInput {
  slug: string;
  displayName: string;
  /** Optional plain-text summary; omitted from the body entirely when unset. */
  description?: string;
  visibility?: Visibility;
}

const VersionListSchema = z.array(VersionSchema);

/** Typed client for the portal REST API; responses are validated with the shared schemas. */
export class PortalClient {
  readonly #baseUrl: string;
  readonly #tokenProvider?: TokenProvider;

  /** `token` may be a static string (dev token) or an async provider (OIDC). */
  constructor(baseUrl: string, token?: string | TokenProvider) {
    this.#baseUrl = baseUrl.replace(/\/+$/, "");
    this.#tokenProvider = typeof token === "string" ? async () => token : token;
  }

  async createApp(input: CreateAppInput): Promise<App> {
    const result = await this.#json(CreateAppResultSchema, "POST", "/api/v1/apps", {
      auth: true,
      body: {
        slug: input.slug,
        displayName: input.displayName,
        // Sent only when set, so a description-free create posts exactly the
        // body it always did — an older portal never sees a new key at all.
        ...(input.description !== undefined ? { description: input.description } : {}),
        ...(input.visibility !== undefined ? { visibility: input.visibility } : {}),
      },
    });
    return result;
  }

  /** Public IdP discovery info — how `helix login` finds the issuer. */
  getAuthConfig(): Promise<AuthConfigResponse> {
    return this.#json(AuthConfigResponseSchema, "GET", "/api/v1/auth/config", {});
  }

  /** The authenticated actor, per the portal — powers `helix whoami`. */
  me(): Promise<PortalMeResponse> {
    return this.#json(PortalMeResponseSchema, "GET", "/api/v1/me", { auth: true });
  }

  /**
   * The deployment-rendered agent skill (`GET /api/v1/skill`, ADR-0036) —
   * `text/markdown`, already substituted with this deployment's hosts, servable
   * models, and approval baselines. Authed like every other `/api/v1` read.
   * Powers `helix skill`.
   */
  getSkill(): Promise<string> {
    return this.#text("/api/v1/skill", { auth: true });
  }

  listVersions(slug: string): Promise<Version[]> {
    // `auth: true` — portal reads are sign-in-gated too (ADR-0024); only
    // /health and the auth-config bootstrap are public.
    return this.#json(VersionListSchema, "GET", `/api/v1/apps/${enc(slug)}/versions`, {
      auth: true,
    });
  }

  promote(slug: string, number: number): Promise<App> {
    return this.#json(AppSchema, "POST", `/api/v1/apps/${enc(slug)}/versions/${number}/promote`, {
      auth: true,
    });
  }

  rollback(slug: string, toNumber?: number): Promise<App> {
    return this.#json(AppSchema, "POST", `/api/v1/apps/${enc(slug)}/rollback`, {
      auth: true,
      body: toNumber !== undefined ? { toNumber } : {},
    });
  }

  async uploadVersion(
    slug: string,
    zip: Buffer,
    filename = "bundle.zip",
  ): Promise<UploadVersionResponse> {
    const form = new FormData();
    form.append("bundle", new Blob([new Uint8Array(zip)]), filename);
    const res = await fetch(this.#url(`/api/v1/apps/${enc(slug)}/versions`), {
      method: "POST",
      headers: await this.#authHeaders(true),
      body: form,
    });
    return this.#parse(UploadVersionResponseSchema, res);
  }

  #url(path: string): string {
    return `${this.#baseUrl}${path}`;
  }

  async #authHeaders(auth: boolean): Promise<Record<string, string>> {
    if (!auth) return {};
    const token = await this.#tokenProvider?.();
    if (!token) {
      throw new CliError("not signed in; run `helix login` (or set HELIX_TOKEN / pass --token)");
    }
    return { authorization: `Bearer ${token}` };
  }

  async #json<T>(
    schema: z.ZodType<T>,
    method: string,
    path: string,
    opts: { auth?: boolean; body?: unknown },
  ): Promise<T> {
    const headers = await this.#authHeaders(opts.auth ?? false);
    if (opts.body !== undefined) headers["content-type"] = "application/json";
    const res = await fetch(this.#url(path), {
      method,
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    return this.#parse(schema, res);
  }

  async #parse<T>(schema: z.ZodType<T>, res: Response): Promise<T> {
    const text = await res.text();
    const data: unknown = text ? JSON.parse(text) : undefined;
    if (!res.ok) {
      const parsed = ApiErrorSchema.safeParse(data);
      if (parsed.success) throw new CliError(parsed.data.error.message, parsed.data.error.code);
      throw new CliError(`request failed (HTTP ${res.status})`);
    }
    return schema.parse(data);
  }

  /** A non-JSON GET (the markdown skill) — errors still typed via the envelope. */
  async #text(path: string, opts: { auth?: boolean }): Promise<string> {
    const headers = await this.#authHeaders(opts.auth ?? false);
    const res = await fetch(this.#url(path), { method: "GET", headers });
    const body = await res.text();
    if (!res.ok) {
      const data: unknown = body ? safeJsonParse(body) : undefined;
      const parsed = ApiErrorSchema.safeParse(data);
      if (parsed.success) throw new CliError(parsed.data.error.message, parsed.data.error.code);
      throw new CliError(`request failed (HTTP ${res.status})`);
    }
    return body;
  }
}

function enc(segment: string): string {
  return encodeURIComponent(segment);
}

/** JSON.parse that swallows the error — for probing an error body that may not be JSON. */
function safeJsonParse(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}
