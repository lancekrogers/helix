import type { CounterStore } from "../gateway/counterStore.js";

/** Max `csp_reports` INSERTs per app within {@link CSP_REPORT_INSERT_WINDOW_MS}. */
export const CSP_REPORT_INSERT_MAX = 100;
/** Per-app insert cap window (10 minutes). */
export const CSP_REPORT_INSERT_WINDOW_MS = 10 * 60_000;

export interface CspReportInsertThrottleOptions {
  max?: number;
  windowMs?: number;
}

/**
 * In-memory per-app cap on CSP report rows — same shape as {@link DenialThrottle}
 * on the fetch allowlist denials. Counting continues past the cap; only the INSERT
 * is skipped.
 */
export class CspReportInsertThrottle {
  readonly #max: number;
  readonly #windowMs: number;
  readonly #store: CounterStore;

  constructor(store: CounterStore, opts: CspReportInsertThrottleOptions = {}) {
    this.#max = opts.max ?? CSP_REPORT_INSERT_MAX;
    this.#windowMs = opts.windowMs ?? CSP_REPORT_INSERT_WINDOW_MS;
    this.#store = store;
  }

  /** Reserve one report against the app's window budget. */
  async admit(appId: string): Promise<{ insert: boolean }> {
    const count = await this.#store.bump(`csp-report:${appId}`, this.#windowMs);
    return { insert: count <= this.#max };
  }
}
