import { afterEach, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_SHUTDOWN_GRACE_MS,
  installGracefulShutdown,
  processShutdownSignal,
  resetProcessShutdownSignalForTests,
  resolveShutdownGraceMs,
  SHUTDOWN_ABORT_MARGIN_MS,
  type ShutdownLogger,
} from "./lifecycle.js";

type SignalHandler = (signal: NodeJS.Signals) => void;
/** The one mocked `process.exit` shape the drain tests wait on. */
type ExitMock = { mock: { calls: unknown[] } };

/**
 * Capture the handlers `installGracefulShutdown` registers WITHOUT registering
 * them on the vitest process — a real SIGTERM mid-suite would otherwise try to
 * drain a fake app. The spy swallows the registration entirely; tests invoke
 * the captured handler directly.
 */
function captureRegistration(): Map<NodeJS.Signals, SignalHandler> {
  const handlers = new Map<NodeJS.Signals, SignalHandler>();
  vi.spyOn(process, "once").mockImplementation(((
    signal: NodeJS.Signals,
    handler: SignalHandler,
  ) => {
    handlers.set(signal, handler);
    return process;
  }) as unknown as typeof process.once);
  return handlers;
}

const silentLog: ShutdownLogger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };

/**
 * Wait for the drain's `finally` to run — signalled by the exit call, not by
 * counting microtask turns (a chain that outlives its test hits vitest's
 * `process.exit` stub after the mocks are restored, which reports as an
 * unhandled rejection). Each `setImmediate` yields a full turn, flushing every
 * pending microtask chain before the check.
 */
async function untilDrained(exit: ExitMock): Promise<void> {
  for (let i = 0; i < 100 && exit.mock.calls.length === 0; i++) {
    await new Promise((r) => setImmediate(r));
  }
  expect(exit.mock.calls.length).toBeGreaterThan(0);
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  resetProcessShutdownSignalForTests();
});

describe("resolveShutdownGraceMs", () => {
  it("defaults when unset or blank", () => {
    expect(resolveShutdownGraceMs({})).toBe(DEFAULT_SHUTDOWN_GRACE_MS);
    expect(resolveShutdownGraceMs({ SHUTDOWN_GRACE_MS: "" })).toBe(DEFAULT_SHUTDOWN_GRACE_MS);
    expect(resolveShutdownGraceMs({ SHUTDOWN_GRACE_MS: "  " })).toBe(DEFAULT_SHUTDOWN_GRACE_MS);
  });

  it("parses a positive millisecond value", () => {
    expect(resolveShutdownGraceMs({ SHUTDOWN_GRACE_MS: "25000" })).toBe(25_000);
    expect(resolveShutdownGraceMs({ SHUTDOWN_GRACE_MS: "500" })).toBe(500);
  });

  it("refuses garbage, zero and negatives, naming the variable", () => {
    for (const bad of ["abc", "0", "-1000", "1e999"]) {
      expect(() => resolveShutdownGraceMs({ SHUTDOWN_GRACE_MS: bad })).toThrow(/SHUTDOWN_GRACE_MS/);
    }
  });
});

describe("installGracefulShutdown", () => {
  it("registers SIGTERM and SIGINT via process.once", () => {
    const handlers = captureRegistration();
    installGracefulShutdown({ close: async () => {} }, silentLog);
    expect(handlers.get("SIGTERM")).toBeTypeOf("function");
    expect(handlers.get("SIGINT")).toBeTypeOf("function");
  });

  it("drains and exits 0 once close resolves", async () => {
    const handlers = captureRegistration();
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    const close = vi.fn(async () => {});
    installGracefulShutdown({ close }, silentLog, { graceMs: 5_000 });

    handlers.get("SIGTERM")!("SIGTERM");

    expect(processShutdownSignal().aborted).toBe(false);
    expect(close).toHaveBeenCalledTimes(1);
    // Not before the drain finishes.
    expect(exit.mock.calls.length).toBe(0);
    await untilDrained(exit);
    expect(exit).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledWith(0);
  });

  it("exits 0 (after logging) even when close rejects", async () => {
    const handlers = captureRegistration();
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    const error = vi.fn();
    const close = vi.fn(async () => {
      throw new Error("hook exploded");
    });
    installGracefulShutdown({ close }, { ...silentLog, error }, { graceMs: 5_000 });

    handlers.get("SIGTERM")!("SIGTERM");

    await untilDrained(exit);
    expect(exit).toHaveBeenCalledWith(0);
    expect(error).toHaveBeenCalledWith(
      expect.objectContaining({ event: "shutdown.error" }),
      "close failed during shutdown",
    );
  });

  it("does not abort in-flight work until graceMs minus the shutdown margin", async () => {
    vi.useFakeTimers();
    const handlers = captureRegistration();
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    const graceMs = 10_000;
    const close = vi.fn(() => new Promise<void>(() => {}));
    installGracefulShutdown({ close }, silentLog, { graceMs });

    handlers.get("SIGTERM")!("SIGTERM");
    expect(processShutdownSignal().aborted).toBe(false);

    await vi.advanceTimersByTimeAsync(graceMs - SHUTDOWN_ABORT_MARGIN_MS - 1);
    expect(processShutdownSignal().aborted).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    expect(processShutdownSignal().aborted).toBe(true);

    vi.useRealTimers();
    expect(exit.mock.calls.length).toBe(0);
  });

  it("aborts in-flight work immediately when grace is at or below the margin", async () => {
    const handlers = captureRegistration();
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    installGracefulShutdown({ close: async () => {} }, silentLog, {
      graceMs: SHUTDOWN_ABORT_MARGIN_MS,
    });

    handlers.get("SIGTERM")!("SIGTERM");
    expect(processShutdownSignal().aborted).toBe(true);
    await untilDrained(exit);
  });

  it("exits at the hard deadline when close hangs", () => {
    vi.useFakeTimers();
    const handlers = captureRegistration();
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    const warn = vi.fn();
    const close = vi.fn(() => new Promise<void>(() => {})); // never settles
    installGracefulShutdown({ close }, { ...silentLog, warn }, { graceMs: 25 });

    handlers.get("SIGTERM")!("SIGTERM");
    expect(exit.mock.calls.length).toBe(0);

    vi.advanceTimersByTime(25);
    vi.runAllTimers(); // the exit rides a queued setImmediate (the flush tick)
    expect(exit).toHaveBeenCalledWith(0);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ event: "shutdown.timeout", graceMs: 25 }),
      "shutdown deadline exceeded — in-flight work did not finish; exiting",
    );
  });

  it("does not exit before the deadline while close is still in flight", () => {
    vi.useFakeTimers();
    const handlers = captureRegistration();
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    const close = vi.fn(() => new Promise<void>(() => {}));
    installGracefulShutdown({ close }, silentLog, { graceMs: 5_000 });

    handlers.get("SIGTERM")!("SIGTERM");
    vi.advanceTimersByTime(4_999);
    expect(exit.mock.calls.length).toBe(0);
    vi.advanceTimersByTime(1);
    vi.runAllTimers(); // the exit rides a queued setImmediate (the flush tick)
    expect(exit).toHaveBeenCalledWith(0);
  });

  it("ignores a second signal during the drain", async () => {
    const handlers = captureRegistration();
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    const close = vi.fn(async () => {});
    installGracefulShutdown({ close }, silentLog, { graceMs: 5_000 });

    handlers.get("SIGTERM")!("SIGTERM");
    handlers.get("SIGINT")!("SIGINT");
    handlers.get("SIGTERM")!("SIGTERM");

    await untilDrained(exit);
    expect(close).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledTimes(1);
  });

  it("logs the signal and grace period on entry", async () => {
    const handlers = captureRegistration();
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    const info = vi.fn();
    installGracefulShutdown({ close: async () => {} }, { ...silentLog, info }, { graceMs: 1_234 });

    handlers.get("SIGTERM")!("SIGTERM");

    await untilDrained(exit);
    expect(info).toHaveBeenCalledWith(
      expect.objectContaining({ event: "shutdown.signal", signal: "SIGTERM", graceMs: 1_234 }),
      expect.stringContaining("SIGTERM"),
    );
  });

  it("resolves the grace period from the injected env", async () => {
    const handlers = captureRegistration();
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    const info = vi.fn();
    installGracefulShutdown(
      { close: async () => {} },
      { ...silentLog, info },
      {
        env: { SHUTDOWN_GRACE_MS: "750" },
      },
    );
    expect(handlers.size).toBe(2);

    handlers.get("SIGINT")!("SIGINT");

    await untilDrained(exit);
    expect(info).toHaveBeenCalledWith(
      expect.objectContaining({ event: "shutdown.signal", signal: "SIGINT", graceMs: 750 }),
      expect.any(String),
    );
  });

  it("throws at install time on a bad SHUTDOWN_GRACE_MS", () => {
    captureRegistration();
    expect(() =>
      installGracefulShutdown({ close: async () => {} }, silentLog, {
        env: { SHUTDOWN_GRACE_MS: "soon" },
      }),
    ).toThrow(/SHUTDOWN_GRACE_MS/);
  });
});
