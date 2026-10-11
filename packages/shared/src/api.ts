import { z } from "zod";
import { APP_DESCRIPTION_MAX, AppSchema } from "./app.js";
import { DeltaSchema } from "./approval.js";
import { CapabilitiesSchema } from "./manifest.js";
import { VersionSchema } from "./version.js";
import { WritableVisibilitySchema } from "./visibility.js";

/**
 * The portal's versioned REST contract (architecture §7, project plan §1).
 * These request/response shapes are the wire boundary shared between the portal
 * and the `azx` CLI (and a future SPA), so they live in @azx-pbc/shared and are
 * validated on both ends.
 */

/** `POST /api/v1/apps` body. Visibility defaults to internal (architecture §4.2). */
export const CreateAppRequestSchema = z.object({
  slug: AppSchema.shape.slug,
  displayName: AppSchema.shape.displayName,
  /** Optional one-line plain-text summary; rendered as a subtitle in the portal. */
  description: AppSchema.shape.description,
  visibility: WritableVisibilitySchema.default({ mode: "internal" }),
  /** Optional per-app capability grant set at create time (architecture §6.3). */
  capabilities: CapabilitiesSchema.optional(),
});
export type CreateAppRequest = z.infer<typeof CreateAppRequestSchema>;

/**
 * `POST /api/v1/apps` response under the capability write-gate (§3). The app
 * fields sit at the top level for backward compatibility with clients that parse
 * `AppSchema` only; `applied` and `pending` are additive.
 */
export const CreateAppResultSchema = AppSchema.extend({
  applied: z.array(DeltaSchema),
  pending: z.string().nullable(),
});
export type CreateAppResult = z.infer<typeof CreateAppResultSchema>;

/**
 * `PATCH /api/v1/apps/:slug` body — partial registry-record edit. Only the keys
 * present are applied: absent = no change, `null` = clear, a string = set.
 * Starts with `description` alone; displayName or other registry fields can
 * join without a second endpoint.
 */
export const UpdateAppRequestSchema = z.object({
  description: z.string().max(APP_DESCRIPTION_MAX).nullable().optional(),
});
export type UpdateAppRequest = z.infer<typeof UpdateAppRequestSchema>;

/** `PUT /api/v1/apps/:slug/manifest` body — replaces the app's capability grants. */
export const SetManifestRequestSchema = z.object({
  capabilities: CapabilitiesSchema,
  /** Justification carried onto an approval request for any elevated deltas. */
  reason: z.string().max(2000).optional(),
});
export type SetManifestRequest = z.infer<typeof SetManifestRequestSchema>;

/** `POST /api/v1/apps/:slug/visibility` body — change how the app gates access. */
export const SetVisibilityRequestSchema = z.object({
  visibility: WritableVisibilitySchema,
  /** Justification carried onto the approval request when going public. */
  reason: z.string().max(2000).optional(),
});
export type SetVisibilityRequest = z.infer<typeof SetVisibilityRequestSchema>;

/** A manually-set shared password must clear this bar (a generated one far exceeds it). */
export const MIN_PASSWORD_LENGTH = 12;

/**
 * Body for `POST /api/v1/apps/:slug/access/password/rotate`. Omit `password` to
 * reroll a fresh xkcd-style passphrase; supply one to set it manually (the
 * shared-credential feature — see docs/features/authentication.md).
 */
export const SetPasswordRequestSchema = z.object({
  password: z.string().min(MIN_PASSWORD_LENGTH).optional(),
});
export type SetPasswordRequest = z.infer<typeof SetPasswordRequestSchema>;

/**
 * Response from the password-access endpoints — the cleartext credential the
 * owner shares out-of-band. Returned only over authenticated portal routes;
 * never present in the manifest or any open read.
 */
export const PasswordCredentialResponseSchema = z.object({
  /** The shared passphrase, in cleartext, for the owner to copy/share. */
  password: z.string().min(1),
  /** The app's public URL, prebuilt so the UI can offer a one-click copy. */
  url: z.url(),
  /** When the current password was set (ISO 8601). */
  setAt: z.string(),
});
export type PasswordCredentialResponse = z.infer<typeof PasswordCredentialResponseSchema>;

/** A single deploy-time advisory from the CSP courtesy lint (architecture §4.4). */
export const CspWarningSchema = z.object({
  file: z.string(),
  origin: z.string(),
  hint: z.string(),
});
export type CspWarning = z.infer<typeof CspWarningSchema>;

/** `POST /api/v1/apps/:slug/access/origin` body — request one external origin. */
export const OriginGrantRequestSchema = z.object({
  origin: z.url(),
  reason: z.string().max(2000).optional(),
});
export type OriginGrantRequest = z.infer<typeof OriginGrantRequestSchema>;

/** One aggregated runtime CSP violation (docs/design/approvals.md §6.2). */
export const CspViolationSchema = z.object({
  appId: z.string(),
  appSlug: z.string().nullable(),
  directive: z.string(),
  blockedUri: z.string(),
  count: z.number().int(),
  lastSeen: z.string(),
  /**
   * The blocked origin is already permitted by the app's *current* manifest, so
   * this historical report is no longer actionable. Derived at read time
   * (directive-aware — only `connect-src`/`img-src` are widened by an
   * `externalOrigins` grant); the row itself is never deleted.
   */
  resolved: z.boolean(),
});
export type CspViolation = z.infer<typeof CspViolationSchema>;

/** `GET /api/v1/csp/violations` response. */
export const CspViolationsPageSchema = z.object({
  violations: z.array(CspViolationSchema),
});
export type CspViolationsPage = z.infer<typeof CspViolationsPageSchema>;

/** `POST /api/v1/apps/:slug/versions` response — the new (preview) version + lint warnings. */
export const UploadVersionResponseSchema = z.object({
  version: VersionSchema,
  warnings: z.array(CspWarningSchema),
});
export type UploadVersionResponse = z.infer<typeof UploadVersionResponseSchema>;

/** `POST /api/v1/apps/:slug/rollback` body. Omit `toNumber` to step back to the previous live version. */
export const RollbackRequestSchema = z.object({
  toNumber: z.int().positive().optional(),
});
export type RollbackRequest = z.infer<typeof RollbackRequestSchema>;

/** Stable error codes, mapped to HTTP status by the portal's error handler. */
export const API_ERROR_CODES = [
  "validation_failed",
  "not_found",
  "slug_taken",
  "bundle_invalid",
  "unauthorized",
  /** Authenticated but not allowed — reserved for v1 RBAC. */
  "forbidden",
  "conflict",
  /**
   * Portal: a sensitive provider edit (or a deletion) arrived without its
   * invalidation acknowledgement. HTTP 409 like `conflict`, but
   * distinguishable: the SPA's
   * review panel opens on this code, and `details` carries the impact payload
   * (`ConfirmationRequiredDetailsSchema` in providers.ts) it renders.
   */
  "confirmation_required",
  /** Gateway: requested model is not in the app's manifest allowlist (§6.3). */
  "model_not_allowed",
  /** Gateway: the app's daily token budget is exhausted (§6.1). */
  "quota_exceeded",
  /**
   * Gateway: the anonymous tier's per-IP request budget is exhausted on a
   * `public` app (app-data design §7). Distinct from `quota_exceeded` (per-app
   * daily budget) so the app can tell per-IP throttling apart from running out
   * of its own budget. HTTP 429.
   */
  "rate_limited",
  /**
   * Gateway: a `shared` app-data write carried no concurrency precondition
   * (`If-Match` / `If-None-Match`), which that scope requires (ADR-0041).
   * Distinct from `conflict` (a precondition that was stated and lost) because
   * the two demand opposite responses: `conflict` says re-read and retry,
   * `precondition_required` says the app's code is wrong. HTTP 428.
   */
  "precondition_required",
  /** Gateway: a configured capability is not available on this edge. */
  "capability_unavailable",
  "internal",
] as const;
export const ApiErrorCodeSchema = z.enum(API_ERROR_CODES);
export type ApiErrorCode = z.infer<typeof ApiErrorCodeSchema>;

/** Uniform error envelope returned by every non-2xx response. */
export const ApiErrorSchema = z.object({
  error: z.object({
    code: ApiErrorCodeSchema,
    message: z.string(),
    details: z.unknown().optional(),
  }),
});
export type ApiError = z.infer<typeof ApiErrorSchema>;
