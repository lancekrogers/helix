/**
 * Graceful shutdown for server entrypoints. Fastify does not install signal
 * handlers; server.ts uses this helper to close connections, pools, and
 * telemetry on SIGTERM/SIGINT.
 *
 * Fastify closes idle connections but waits for active requests. Long-lived
 * SSE streams may outlast shutdown, so a hard deadline forces exit. In-flight
 * gateway work is aborted shortly before that deadline so cut rows and lease
 * release can finish inside the drain; streams that complete earlier are left
 * alone. The default 10-second grace period fits inside ACA's documented
 * 30-second stop window. Signals may be missed and SIGKILL cannot be handled;
 * the telemetry batch
 * interval limits pending data loss in those cases.
 *
 * Node-only: export through @azx-pbc/shared/lifecycle, outside the barrel used
 * by browser code.
 */

/** Structural logger — the pino surface, without importing Fastify. */
export interface ShutdownLogger {
  info(obj: Record<string, unknown>, msg: string): void;
  warn(obj: Record<string, unknown>, msg: string): void;
  error(obj: Record<string, unknown>, msg: string): void;
}

/** Structural Fastify instance — `app.close()`, nothing else. */
export interface ShutdownTarget {
  close(): Promise<void>;
}

/**
 * 10 s — a third of Container Apps' documented 30 s SIGTERM-to-SIGKILL window.
 * Generous for the drain's real beneficiary (short requests: assets, `/_api/*`
 * data calls, auth callbacks — all well under a second) and for the `onClose`
 * teardown chain, while bounded enough that a deploy costs seconds, not tens.
 * Long-lived SSE streams are cut at the deadline either way: no sane value
 * saves them, which is exactly why the deadline is hard rather than advisory.
 */
export const DEFAULT_SHUTDOWN_GRACE_MS = 10_000;

/**
 * How long before the hard shutdown deadline to abort in-flight gateway work (LLM streams,
 * etc.). Leaves room for the cut path and lease release before `process.exit`.
 */
export const SHUTDOWN_ABORT_MARGIN_MS = 3_000;

const SIGNALS = ["SIGTERM", "SIGINT"] as const;

/** Aborted on shutdown so in-flight upstream work can cut and release leases. */
let processShutdownController = new AbortController();

/** Combined into gateway upstream `AbortSignal.any` (edge LLM, etc.). */
export function processShutdownSignal(): AbortSignal {
  return processShutdownController.signal;
}

/** Abort in-flight gateway work when a drain starts. Tests may call directly. */
export function abortInFlightWorkForShutdown(): void {
  processShutdownController.abort();
}

/** @internal Vitest-only: replace an already-aborted controller between cases. */
export function resetProcessShutdownSignalForTests(): void {
  processShutdownController = new AbortController();
}

/**
 * Resolve `SHUTDOWN_GRACE_MS`, or the {@link DEFAULT_SHUTDOWN_GRACE_MS}.
 *
 * Thrown, not coerced, on garbage — the same stance as every other validated
 * boot duration in the platform: every comparison against `NaN` is false, so a
 * mistyped value would otherwise silently disable the deadline, turning the
 * drain hang the deadline exists to prevent into the default behaviour again.
 */
export function resolveShutdownGraceMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.SHUTDOWN_GRACE_MS;
  if (raw === undefined || raw.trim() === "") return DEFAULT_SHUTDOWN_GRACE_MS;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(
      `SHUTDOWN_GRACE_MS must be a positive number of milliseconds (got ${JSON.stringify(raw)})`,
    );
  }
  return value;
}

export interface GracefulShutdownOptions {
  /** Overrides `SHUTDOWN_GRACE_MS` from `env`; defaults to {@link resolveShutdownGraceMs}. */
  graceMs?: number;
  /** Injectable for tests; defaults to `process.env`. */
  env?: NodeJS.ProcessEnv;
  /** Injectable for tests; defaults to `SIGTERM` + `SIGINT`. */
  signals?: readonly NodeJS.Signals[];
}

/**
 * Install `SIGTERM`/`SIGINT` handlers that drain `target` under a hard
 * deadline, then exit. Call once from each `server.ts`, after `buildApp()` has
 * produced the logger and before or after `listen` — the teardown hooks are
 * guarded, so a signal during boot is as safe as one at rest.
 *
 * On a signal: log, schedule in-flight abort at `graceMs - SHUTDOWN_ABORT_MARGIN_MS`
 * (immediate when grace is at or below the margin), start the (unref'd) hard deadline,
 * `close()`, exit 0 — including when `close()` rejects. A second signal during the
 * drain is a no-op; forcing past a stuck drain is SIGKILL's job, and the orchestrator
 * has it.
 */
export function installGracefulShutdown(
  target: ShutdownTarget,
  log: ShutdownLogger,
  options: GracefulShutdownOptions = {},
): void {
  const graceMs = options.graceMs ?? resolveShutdownGraceMs(options.env ?? process.env);
  const signals = options.signals ?? SIGNALS;

  let stopping = false;
  /**
   * Yield one macrotask turn before exiting so the async stdout destination
   * flushes the line just written — pino buffers, and a `process.exit` in the
   * same tick as the write loses it. Queued immediates are ref-holding, so
   * this turn always runs.
   */
  const exitSoon = (): void => {
    setImmediate(() => process.exit(0));
  };
  const onSignal = (signal: NodeJS.Signals): void => {
    if (stopping) return;
    stopping = true;
    let abortTimer: NodeJS.Timeout | undefined;
    if (graceMs <= SHUTDOWN_ABORT_MARGIN_MS) {
      abortInFlightWorkForShutdown();
    } else {
      abortTimer = setTimeout(() => {
        abortInFlightWorkForShutdown();
      }, graceMs - SHUTDOWN_ABORT_MARGIN_MS);
      abortTimer.unref();
    }
    log.info(
      { event: "shutdown.signal", signal, graceMs },
      `${signal} received — draining in-flight requests (hard deadline ${graceMs} ms)`,
    );
    const deadline = setTimeout(() => {
      // The unref below means this fires only while the event loop is still
      // alive on real work (in-flight sockets); a loop that drained on its own
      // exits without us, which is the same outcome.
      log.warn(
        { event: "shutdown.timeout", graceMs },
        "shutdown deadline exceeded — in-flight work did not finish; exiting",
      );
      exitSoon();
    }, graceMs);
    deadline.unref(); // the drain must never be what holds the process open
    void target
      .close()
      .catch((err: unknown) => {
        // A hook that fails mid-teardown must not change the exit story: the
        // replica is being replaced regardless. Log and go.
        log.error({ event: "shutdown.error", err }, "close failed during shutdown");
      })
      .finally(() => {
        if (abortTimer !== undefined) clearTimeout(abortTimer);
        clearTimeout(deadline);
        log.info({ event: "shutdown.exit" }, "drain complete — exiting");
        exitSoon();
      });
  };

  for (const signal of signals) process.once(signal, onSignal);
}
