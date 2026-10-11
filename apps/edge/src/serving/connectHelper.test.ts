import { webcrypto } from "node:crypto";
import vm from "node:vm";
import { describe, expect, it } from "vitest";
import {
  ConsentAttemptTagSchema,
  CONNECT_MESSAGE_VERSION,
  CONSENT_ATTEMPT_TTL_SECONDS,
  CONSENT_MESSAGE_OUTCOMES,
  CONSENT_MESSAGE_REASONS,
  HELIX_CONNECT_MESSAGE_SOURCE,
  type ConnectOutcomeMessage,
} from "@azx-pbc/shared";
import { ROUTE_CONSENT_CANCEL, ROUTE_CONSENT_START } from "@azx-pbc/shared/telemetry";
import { buildApp } from "../app.js";
import { controlOrigin, publicOrigin } from "../config.js";
import { splitEdgeConfig, testEdgeConfig } from "../test/config.js";
import { FakeBlobReader, FakeRegistry, registryEntry } from "../test/fakes.js";
import type { ProxiedOriginCredential } from "../registry/projection.js";
import { buildConnectScript } from "./connectHelper.js";

/**
 * The connect helper. The script
 * is platform-authored inline JS, so its behavior is driven here in a scripted
 * browser-shaped sandbox: the REAL built script evaluates against fake
 * `window`/timers, and the tests drive gestures, messages, popup closes and
 * clock advances by hand. Nothing of the helper is re-implemented in the tests
 * — the string the edge ships is the thing under test.
 *
 * The HTTP-level half (below) proves the injection gating: the helper ships
 * only under the manifest's `shim.connect` grant, the
 * fetch shim's own behavior is untouched, and the receiver-verification
 * origins are the app host + the auth host.
 */

const APP_ORIGIN = "https://demo.local.helix.azxlabs.io:8080";
const AUTH_ORIGIN = "https://auth.local.helix.azxlabs.io:8080";
const VENDOR_ORIGIN = "https://vendor.example";
const PLATFORM_ORIGINS = [APP_ORIGIN, AUTH_ORIGIN];
const CANCEL_URL = `${APP_ORIGIN}${ROUTE_CONSENT_CANCEL}`;

/** A valid completion message the way a platform popup page posts it. */
function message(overrides: Partial<ConnectOutcomeMessage> = {}): ConnectOutcomeMessage {
  return {
    source: HELIX_CONNECT_MESSAGE_SOURCE,
    version: CONNECT_MESSAGE_VERSION,
    provider: "asana",
    outcome: "connected",
    reason: null,
    ...overrides,
  };
}

/** A manual clock — the helper's poll interval and five-minute deadline are
 * driven deterministically, with the shipped constants untouched. */
class ManualClock {
  #now = 0;
  #seq = 0;
  #timers = new Map<number, { at: number; interval: number | null; fn: () => void }>();

  setTimeout(fn: () => void, ms: number): number {
    return this.#schedule(fn, ms, null);
  }

  setInterval(fn: () => void, ms: number): number {
    return this.#schedule(fn, ms, ms);
  }

  #schedule(fn: () => void, ms: number, interval: number | null): number {
    const id = ++this.#seq;
    this.#timers.set(id, { at: this.#now + ms, interval, fn });
    return id;
  }

  clearTimeout(id: number): void {
    this.#timers.delete(id);
  }

  /** Run every timer due within `ms`, in time order (newly scheduled ones too). */
  advance(ms: number): void {
    const end = this.#now + ms;
    for (;;) {
      const due = [...this.#timers.entries()]
        .filter(([, t]) => t.at <= end)
        .sort((a, b) => a[1].at - b[1].at || a[0] - b[0]);
      if (due.length === 0) break;
      const [id, timer] = due[0]!;
      this.#now = Math.max(this.#now, timer.at);
      if (timer.interval === null) this.#timers.delete(id);
      else timer.at = this.#now + timer.interval;
      timer.fn();
    }
    this.#now = end;
  }

  /** Live timers — the leak assertion (an uncleared poll interval survives). */
  get pendingCount(): number {
    return this.#timers.size;
  }
}

interface RecordedFetch {
  url: string;
  method: string | undefined;
  credentials: string | undefined;
  body: unknown;
}

interface FakePopup {
  closed: boolean;
}

/**
 * The browser-shaped sandbox: `window` with addEventListener/open/fetch/
 * location/crypto, timers wired to the manual clock. `dispatchMessage` plays
 * the browser delivering a postMessage event to the page.
 */
function createSandbox(opts: { openReturns?: FakePopup | null; fetchRejects?: boolean } = {}) {
  const clock = new ManualClock();
  const listeners = new Map<string, ((event: unknown) => void)[]>();
  const addedTypes: string[] = [];
  const removedTypes: string[] = [];
  const opens: { url: string; features: string }[] = [];
  const fetches: RecordedFetch[] = [];

  const addEventListener = (type: string, fn: (event: unknown) => void): void => {
    addedTypes.push(type);
    const list = listeners.get(type) ?? [];
    list.push(fn);
    listeners.set(type, list);
  };
  const removeEventListener = (type: string, fn: (event: unknown) => void): void => {
    removedTypes.push(type);
    const list = listeners.get(type) ?? [];
    const at = list.indexOf(fn);
    if (at >= 0) list.splice(at, 1);
  };

  const popup: FakePopup = { closed: false };
  const windowObj: {
    location: { origin: string };
    crypto: { getRandomValues(array: Uint8Array): Uint8Array };
    addEventListener: (type: string, fn: (event: unknown) => void) => void;
    removeEventListener: (type: string, fn: (event: unknown) => void) => void;
    open: (url: string, target: string, features: string) => FakePopup | null;
    fetch: (
      url: string,
      init?: { method?: string; credentials?: string; body?: string },
    ) => Promise<unknown>;
    helix?: { connect?: (ref: unknown) => Promise<unknown> };
  } = {
    location: { origin: APP_ORIGIN },
    crypto: webcrypto,
    addEventListener,
    removeEventListener,
    open: (url: string, _target: string, features: string): FakePopup | null => {
      opens.push({ url, features });
      if (opts.openReturns === null) return null;
      return popup;
    },
    // A sentinel: if the helper (or anything it runs) patched fetch, the test
    // sees the identity change — patching is the fetch shim's job, never the
    // helper's.
    fetch: (url: string, init?: { method?: string; credentials?: string; body?: string }) => {
      fetches.push({
        url,
        method: init?.method,
        credentials: init?.credentials,
        body: init?.body === undefined ? undefined : (JSON.parse(init.body) as unknown),
      });
      if (opts.fetchRejects) return Promise.reject(new Error("network down"));
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ outcome: "cancelled" }),
      });
    },
  };

  const sandbox = {
    window: windowObj,
    setTimeout: (fn: () => void, ms: number) => clock.setTimeout(fn, ms),
    clearTimeout: (id: number) => clock.clearTimeout(id),
    setInterval: (fn: () => void, ms: number) => clock.setInterval(fn, ms),
    clearInterval: (id: number) => clock.clearTimeout(id),
  };
  vm.runInNewContext(buildConnectScript({ platformOrigins: PLATFORM_ORIGINS }), sandbox);

  return {
    clock,
    connect: windowObj.helix!.connect!,
    helixObject: windowObj.helix as object,
    opens,
    fetches,
    popup,
    addedTypes,
    removedTypes,
    messageListenerCount: () => (listeners.get("message") ?? []).length,
    dispatchMessage: (event: { source: unknown; origin: string; data: unknown }): void => {
      for (const fn of [...(listeners.get("message") ?? [])]) fn(event);
    },
  };
}

/** Resolve-or-not probe: flush the microtask queue and see whether `p` settled. */
async function resolvedValue(p: Promise<unknown>): Promise<{ settled: boolean; value?: unknown }> {
  let settled = false;
  let value: unknown;
  p.then(
    (v) => {
      settled = true;
      value = v;
    },
    () => {
      settled = true;
    },
  );
  await Promise.resolve();
  await Promise.resolve();
  return { settled, value };
}

describe("the connect helper script — surface", () => {
  it("defines window.helix.connect as a function, and double injection is a no-op", () => {
    const s = createSandbox();
    expect(typeof s.connect).toBe("function");
    // Re-evaluating the same document's script (a platform bug or a future
    // refactor) must not rewrap the function.
    const before = s.helixObject;
    vm.runInNewContext(buildConnectScript({ platformOrigins: PLATFORM_ORIGINS }), {
      window: { __helixConnect: true, helix: before, addEventListener: () => {} },
    });
    expect(s.helixObject).toBe(before);
  });

  it("never patches fetch or XHR — interception is the fetch shim's grant alone", () => {
    // The compatibility promise: an app can hold both
    // grants; the helper must not grow shim behavior of its own.
    const js = buildConnectScript({ platformOrigins: PLATFORM_ORIGINS });
    expect(js).not.toContain("XMLHttpRequest");
    expect(js).not.toContain("window.fetch =");
    expect(js).not.toContain("origFetch");
    expect(js).toContain("//# sourceURL=helix/connect-helper.js");
  });

  it("a user-gesture call opens exactly one popup at the start route with the attempt tag", async () => {
    const s = createSandbox();
    const p = s.connect("asana");
    expect(s.opens).toHaveLength(1);
    const url = new URL(s.opens[0]!.url);
    expect(url.origin).toBe(APP_ORIGIN);
    expect(url.pathname).toBe(ROUTE_CONSENT_START.replace(":ref", "asana"));
    expect(url.searchParams.has("attempt")).toBe(true);
    const tag = url.searchParams.get("attempt") ?? "";
    expect(ConsentAttemptTagSchema.safeParse(tag).success).toBe(true);
    // The popup shape the platform fixes (~520×680, resizable).
    expect(s.opens[0]!.features).toContain("popup=yes");
    expect(s.opens[0]!.features).toContain("resizable=yes");
    expect(s.clock.pendingCount).toBe(2); // poll interval + five-minute deadline
    void p;
  });

  it("builds its URLs from window.location.origin, never document.baseURI", () => {
    // A hostile <base href> in the app document must not be able to move the
    // popup or the cancellation call off the app origin.
    const js = buildConnectScript({ platformOrigins: PLATFORM_ORIGINS });
    expect(js).not.toContain("baseURI");
    expect(js).toContain("window.location.origin");
  });
});

describe("the connect helper script — blocked", () => {
  it("resolves blocked immediately when window.open refuses, with no navigation and no retry", async () => {
    const s = createSandbox({ openReturns: null });
    const { settled, value } = await resolvedValue(s.connect("asana"));
    expect(settled).toBe(true);
    // No attempt was started — no tag on the result, nothing to cancel.
    expect(value).toEqual({ outcome: "blocked", provider: "asana" });
    expect(s.opens).toHaveLength(1); // exactly one attempt, never retried
    expect(s.fetches).toHaveLength(0); // no cancellation to acknowledge
    expect(s.messageListenerCount()).toBe(0);
    expect(s.clock.pendingCount).toBe(0);
  });
});

describe("the connect helper script — receiver verification", () => {
  it("discards a forged message from a sibling window, the vendor's page, or any other origin/source", async () => {
    const s = createSandbox();
    const p = s.connect("asana");
    const tag = new URL(s.opens[0]!.url).searchParams.get("attempt")!;

    const forgeries: {
      name: string;
      event: { source: unknown; origin: string; data: unknown };
    }[] = [
      {
        name: "a sibling window (the app's own second popup)",
        event: {
          source: { fake: "sibling" },
          origin: AUTH_ORIGIN,
          data: message({ attempt: tag }),
        },
      },
      {
        name: "the app's own page — origin is a platform origin, sender is not the popup",
        event: { source: { fake: "self" }, origin: APP_ORIGIN, data: message({ attempt: tag }) },
      },
      {
        name: "the vendor's authorize page",
        event: { source: s.popup, origin: VENDOR_ORIGIN, data: message({ attempt: tag }) },
      },
      {
        name: "any other origin",
        event: { source: s.popup, origin: "https://evil.example", data: message({ attempt: tag }) },
      },
      {
        name: "wrong producer source",
        event: {
          source: s.popup,
          origin: AUTH_ORIGIN,
          data: { ...message({ attempt: tag }), source: "evil" },
        },
      },
      {
        name: "wrong contract version",
        event: {
          source: s.popup,
          origin: AUTH_ORIGIN,
          data: { ...message({ attempt: tag }), version: 2 },
        },
      },
      {
        name: "a different provider",
        event: {
          source: s.popup,
          origin: AUTH_ORIGIN,
          data: message({ provider: "gitlab", attempt: tag }),
        },
      },
      {
        name: "another attempt's tag",
        event: { source: s.popup, origin: AUTH_ORIGIN, data: message({ attempt: "f".repeat(32) }) },
      },
      {
        name: "an outcome outside the bounded vocabulary",
        event: {
          source: s.popup,
          origin: AUTH_ORIGIN,
          data: { ...message({ attempt: tag }), outcome: "pwned" },
        },
      },
      {
        name: "a reason carried with a non-error outcome",
        event: {
          source: s.popup,
          origin: AUTH_ORIGIN,
          data: message({ outcome: "connected", reason: "conflict", attempt: tag }),
        },
      },
      {
        name: "an error reason outside the bounded set",
        event: {
          source: s.popup,
          origin: AUTH_ORIGIN,
          data: { ...message({ outcome: "error", attempt: tag }), reason: "nope" },
        },
      },
      {
        name: "the reason field missing entirely (a producer skew)",
        event: {
          source: s.popup,
          origin: AUTH_ORIGIN,
          data: {
            source: HELIX_CONNECT_MESSAGE_SOURCE,
            version: CONNECT_MESSAGE_VERSION,
            attempt: tag,
            provider: "asana",
            outcome: "connected",
          },
        },
      },
      { name: "a null payload", event: { source: s.popup, origin: AUTH_ORIGIN, data: null } },
      {
        name: "a string payload",
        event: { source: s.popup, origin: AUTH_ORIGIN, data: "connected" },
      },
      { name: "an array payload", event: { source: s.popup, origin: AUTH_ORIGIN, data: [] } },
    ];

    for (const { name, event } of forgeries) {
      s.dispatchMessage(event);
      const { settled } = await resolvedValue(p);
      expect(settled, `a forged message must be discarded: ${name}`).toBe(false);
    }

    // The discards did not wedge the flow: the REAL completion still lands.
    s.dispatchMessage({ source: s.popup, origin: AUTH_ORIGIN, data: message({ attempt: tag }) });
    const { settled, value } = await resolvedValue(p);
    expect(settled).toBe(true);
    expect(value).toEqual({ outcome: "connected", provider: "asana", attempt: tag });
  });

  it("binds a tag-less completion message to the popup it opened (sender + origin verify)", async () => {
    // The completion pages post from the auth host; when the message
    // carries no attempt tag, the sender check is what binds it to this call.
    const s = createSandbox();
    const p = s.connect("asana");
    s.dispatchMessage({ source: s.popup, origin: AUTH_ORIGIN, data: message() });
    const { settled, value } = await resolvedValue(p);
    expect(settled).toBe(true);
    expect(value).toEqual({
      outcome: "connected",
      provider: "asana",
      attempt: new URL(s.opens[0]!.url).searchParams.get("attempt"),
    });
  });
});

describe("the connect helper script — outcome relay", () => {
  it.each([
    ["connected", { outcome: "connected" }],
    ["already_connected", { outcome: "already_connected" }],
    ["denied", { outcome: "denied" }],
    ["signin_required", { outcome: "signin_required" }],
    [
      "error with a bounded reason (the losing saver's conflict)",
      { outcome: "error", reason: "conflict" },
    ],
  ] as const)("relays %s", async (_name, over) => {
    const s = createSandbox();
    const p = s.connect("asana");
    const tag = new URL(s.opens[0]!.url).searchParams.get("attempt")!;
    s.dispatchMessage({
      source: s.popup,
      origin: AUTH_ORIGIN,
      data: message({ ...over, attempt: tag }),
    });
    const { settled, value } = await resolvedValue(p);
    expect(settled).toBe(true);
    expect(value).toEqual({ ...over, provider: "asana", attempt: tag });
  });

  it("relays a schema-valid error message whose reason is null as a reason-less error", async () => {
    const s = createSandbox();
    const p = s.connect("asana");
    const tag = new URL(s.opens[0]!.url).searchParams.get("attempt")!;
    s.dispatchMessage({
      source: s.popup,
      origin: AUTH_ORIGIN,
      data: message({ outcome: "error", reason: null, attempt: tag }),
    });
    const { settled, value } = await resolvedValue(p);
    expect(settled).toBe(true);
    expect(value).toEqual({ outcome: "error", provider: "asana", attempt: tag });
  });
});

describe("the connect helper script — cancelled", () => {
  it("a popup closed without a completion message acknowledges cancellation and resolves cancelled", async () => {
    const s = createSandbox();
    const p = s.connect("asana");
    const tag = new URL(s.opens[0]!.url).searchParams.get("attempt")!;

    s.popup.closed = true;
    s.clock.advance(250);

    const { settled, value } = await resolvedValue(p);
    expect(settled).toBe(true);
    expect(value).toEqual({ outcome: "cancelled", provider: "asana", attempt: tag });
    // The acknowledgement rides the session (same-origin credentials) with the
    // helper's own correlation body — the route maps the tag to the attempt.
    expect(s.fetches).toHaveLength(1);
    expect(s.fetches[0]!.url).toBe(CANCEL_URL);
    expect(s.fetches[0]!.method).toBe("POST");
    expect(s.fetches[0]!.credentials).toBe("same-origin");
    expect(s.fetches[0]!.body).toEqual({ provider: "asana", attempt: tag });
    expect(s.messageListenerCount()).toBe(0);
    expect(s.clock.pendingCount).toBe(0);
  });

  it("resolves cancelled even when the acknowledgement fails — best-effort, fire once", async () => {
    const s = createSandbox({ fetchRejects: true });
    const p = s.connect("asana");
    const tag = new URL(s.opens[0]!.url).searchParams.get("attempt")!;
    s.popup.closed = true;
    s.clock.advance(250);
    const { settled, value } = await resolvedValue(p);
    expect(settled).toBe(true);
    expect(value).toEqual({ outcome: "cancelled", provider: "asana", attempt: tag });
    expect(s.fetches).toHaveLength(1); // fired once — never retried, never replayed
  });

  it("a late message after the close resolves nothing further", async () => {
    const s = createSandbox();
    const p = s.connect("asana");
    const tag = new URL(s.opens[0]!.url).searchParams.get("attempt")!;
    s.popup.closed = true;
    s.clock.advance(250);
    await resolvedValue(p);
    // A forged "connected" after cancellation changes nothing: the outcome was
    // delivered, the listeners are gone — the flip side.
    s.dispatchMessage({ source: s.popup, origin: AUTH_ORIGIN, data: message({ attempt: tag }) });
    expect(s.fetches).toHaveLength(1);
    expect(s.messageListenerCount()).toBe(0);
  });
});

describe("the connect helper script — timeout", () => {
  it("resolves timeout at the five-minute bound with the popup open, and never acknowledges a cancel", async () => {
    const s = createSandbox();
    const p = s.connect("asana");
    const tag = new URL(s.opens[0]!.url).searchParams.get("attempt")!;

    s.clock.advance(CONSENT_ATTEMPT_TTL_SECONDS * 1000 - 1);
    let state = await resolvedValue(p);
    expect(state.settled).toBe(false); // a minute early is still waiting

    s.clock.advance(1);
    state = await resolvedValue(p);
    expect(state.settled).toBe(true);
    expect(state.value).toEqual({ outcome: "timeout", provider: "asana", attempt: tag });
    // The attempt expires server-side regardless — no cancel POST.
    expect(s.fetches).toHaveLength(0);
    expect(s.messageListenerCount()).toBe(0);
    expect(s.clock.pendingCount).toBe(0);

    // A completion after the timeout is nobody's outcome: no second resolve,
    // no new listeners, no new popups.
    s.dispatchMessage({ source: s.popup, origin: AUTH_ORIGIN, data: message({ attempt: tag }) });
    expect(s.opens).toHaveLength(1);
  });
});

describe("the connect helper script — listener lifetime (the four-exit rule)", () => {
  it("repeated open/close cycles accumulate no listeners and no timers", async () => {
    const s = createSandbox();
    let totalAdded = 0;
    let totalRemoved = 0;
    for (let cycle = 0; cycle < 5; cycle++) {
      const before = s.messageListenerCount();
      const addedBefore = s.addedTypes.filter((t) => t === "message").length;
      const removedBefore = s.removedTypes.filter((t) => t === "message").length;
      const p = s.connect("asana");
      expect(s.messageListenerCount()).toBe(before + 1); // acquired
      // Each exit in turn across the cycles: close, message, timeout.
      if (cycle % 3 === 0) {
        s.popup.closed = true;
        s.clock.advance(250);
      } else if (cycle % 3 === 1) {
        const tag = new URL(s.opens[cycle]!.url).searchParams.get("attempt")!;
        s.dispatchMessage({
          source: s.popup,
          origin: AUTH_ORIGIN,
          data: message({ attempt: tag }),
        });
      } else {
        s.clock.advance(CONSENT_ATTEMPT_TTL_SECONDS * 1000);
      }
      const { settled } = await resolvedValue(p);
      expect(settled).toBe(true);
      expect(s.messageListenerCount()).toBe(before); // released
      totalAdded += s.addedTypes.filter((t) => t === "message").length - addedBefore;
      totalRemoved += s.removedTypes.filter((t) => t === "message").length - removedBefore;
      expect(s.clock.pendingCount).toBe(0); // poll + deadline both gone
    }
    // The acquire/release ledger balances exactly — nothing accumulated.
    expect(totalAdded).toBe(5);
    expect(totalRemoved).toBe(5);
  });
});

describe("the connect helper script — no replay, no automatic behavior", () => {
  it("after connected, the helper makes no calls and opens no popups of its own", async () => {
    const s = createSandbox();
    const p = s.connect("asana");
    const tag = new URL(s.opens[0]!.url).searchParams.get("attempt")!;
    s.dispatchMessage({ source: s.popup, origin: AUTH_ORIGIN, data: message({ attempt: tag }) });
    await resolvedValue(p);
    // No retry of the start, no cancellation, no watch on any response: the
    // app decides what happens next.
    expect(s.opens).toHaveLength(1);
    expect(s.fetches).toHaveLength(0);
    expect(s.messageListenerCount()).toBe(0);
    expect(s.clock.pendingCount).toBe(0);
  });

  it("a malformed provider ref resolves a bounded error without opening anything", async () => {
    const s = createSandbox();
    for (const bad of [
      "NOT A REF",
      "../etc/passwd",
      "asana?x=1",
      "",
      "a".repeat(65),
      42,
      undefined,
    ]) {
      const { settled, value } = await resolvedValue(s.connect(bad));
      expect(settled, String(bad)).toBe(true);
      expect(value).toEqual({
        outcome: "error",
        provider: String(bad),
        reason: "provider_unavailable",
      });
    }
    expect(s.opens).toHaveLength(0);
    expect(s.fetches).toHaveLength(0);
    expect(s.messageListenerCount()).toBe(0);
  });
});

describe("the connect helper script — concurrent calls", () => {
  it("each call gets its own attempt tag, its own popup, and its own outcome", async () => {
    const s = createSandbox();
    const p1 = s.connect("asana");
    const p2 = s.connect("asana");
    expect(s.opens).toHaveLength(2);
    const tag1 = new URL(s.opens[0]!.url).searchParams.get("attempt")!;
    const tag2 = new URL(s.opens[1]!.url).searchParams.get("attempt")!;
    expect(tag1).not.toBe(tag2);

    // Call 2's popup completes; call 1 keeps waiting on its own popup.
    s.dispatchMessage({ source: s.popup, origin: AUTH_ORIGIN, data: message({ attempt: tag2 }) });
    const second = await resolvedValue(p2);
    expect(second.settled).toBe(true);
    expect((second.value as { attempt: string }).attempt).toBe(tag2);
    const firstEarly = await resolvedValue(p1);
    expect(firstEarly.settled).toBe(false);

    // Call 1's popup closes; its acknowledgement carries ITS tag only.
    s.popup.closed = true;
    s.clock.advance(250);
    const first = await resolvedValue(p1);
    expect(first.settled).toBe(true);
    expect(first.value).toEqual({ outcome: "cancelled", provider: "asana", attempt: tag1 });
    expect(s.fetches).toHaveLength(1);
    expect((s.fetches[0]!.body as { attempt: string }).attempt).toBe(tag1);
  });
});

/**
 * The injection gating — at the HTTP surface,
 * against the real serving path. A provider binding is NOT the grant; the
 * manifest's `shim.connect` is.
 */
const HTML = "<!doctype html><html><head></head><body>hi</body></html>";

async function serveIndex(
  entry: ReturnType<typeof registryEntry>,
  config = testEdgeConfig({ allowUnauthenticated: true }),
): Promise<{
  status: number;
  body: string;
  etag: string | undefined;
}> {
  const blob = new FakeBlobReader();
  blob.set(`${entry.blobPrefix}index.html`, {
    body: HTML,
    contentType: "text/html; charset=utf-8",
    etag: '"h1"',
  });
  const app = buildApp({
    config,
    registry: new FakeRegistry([entry]),
    blob,
  });
  try {
    const res = await app.inject({
      url: "/",
      headers: { host: new URL(publicOrigin(config, entry.slug)).host },
    });
    return { status: res.statusCode, body: res.body, etag: res.headers.etag as string | undefined };
  } finally {
    await app.close();
  }
}

describe("helper injection is gated by the manifest's shim.connect grant (adversarial)", () => {
  it("an app granting shim.connect serves the helper, with the platform origins baked in", async () => {
    const res = await serveIndex(
      registryEntry({
        appId: "a1",
        slug: "helper",
        blobPrefix: "apps/h/1/",
        shim: { fetch: false, connect: true },
      }),
    );
    const ownOrigin = "https://helper.local.helix.azxlabs.io:8080";
    expect(res.status).toBe(200);
    expect(res.body).toContain("window.helix.connect");
    expect(res.body).toContain("//# sourceURL=helix/connect-helper.js");
    // Receiver verification's origin set: the app's own host + the auth host.
    expect(res.body).toContain(ownOrigin);
    expect(res.body).toContain(AUTH_ORIGIN);
    // No foreign origin is ever baked.
    expect(res.body).not.toContain(VENDOR_ORIGIN);
    // The cancel route the helper acknowledges to.
    expect(res.body).toContain(ROUTE_CONSENT_CANCEL);
    // Injected bytes ≠ blob etag.
    expect(res.etag).toBeUndefined();
  });

  it("split layout: platform origins use apps + control auth host", async () => {
    const cfg = splitEdgeConfig();
    const slug = "helper";
    const res = await serveIndex(
      registryEntry({
        appId: "a3",
        slug,
        blobPrefix: "apps/h2/1/",
        shim: { fetch: false, connect: true },
      }),
      cfg,
    );
    expect(res.body).toContain(publicOrigin(cfg, slug));
    expect(res.body).toContain(controlOrigin(cfg, "auth"));
    expect(res.body).not.toContain(`auth.${cfg.baseDomain}`);
  });

  it("a provider-bound app WITHOUT shim.connect receives no helper script", async () => {
    const res = await serveIndex(
      registryEntry({
        appId: "a2",
        slug: "bound",
        blobPrefix: "apps/b/1/",
        fetch: {
          connections: new Map<string, ProxiedOriginCredential>([
            ["https://api.asana.com", { kind: "provider", provider: "asana", required: true }],
          ]),
          requestsPerDay: null,
          shim: false,
        },
      }),
    );
    expect(res.status).toBe(200);
    expect(res.body).toBe(HTML); // nothing injected at all
    expect(res.body).not.toContain("window.helix.connect");
    expect(res.etag).toBe('"h1"');
  });

  it("a non-provider-bound app with only shim: {fetch: true} gets the fetch shim and no helper", async () => {
    const res = await serveIndex(
      registryEntry({
        appId: "a3",
        slug: "fetchonly",
        blobPrefix: "apps/f/1/",
        shim: { fetch: true, connect: false },
        fetch: {
          connections: new Map<string, ProxiedOriginCredential>([
            ["https://api.github.com", { kind: "keyless" }],
          ]),
          requestsPerDay: null,
          shim: true,
        },
      }),
    );
    expect(res.status).toBe(200);
    // The fetch shim is exactly as before the helper: both patches, this app's
    // origins, same transparency semantics.
    expect(res.body).toContain("window.fetch =");
    expect(res.body).toContain("XMLHttpRequest.prototype.open");
    expect(res.body).toContain("https://api.github.com");
    expect(res.body).toContain("//# sourceURL=helix/fetch-shim.js");
    // The helper is not there — connect was not granted.
    expect(res.body).not.toContain("window.helix.connect");
    expect(res.body).not.toContain("connect-helper.js");
  });

  it("an app with both grants gets both scripts, the fetch shim first", async () => {
    const res = await serveIndex(
      registryEntry({
        appId: "a4",
        slug: "both",
        blobPrefix: "apps/bo/1/",
        shim: { fetch: true, connect: true },
        fetch: {
          connections: new Map<string, ProxiedOriginCredential>([
            ["https://api.github.com", { kind: "keyless" }],
          ]),
          requestsPerDay: null,
          shim: true,
        },
      }),
    );
    expect(res.status).toBe(200);
    const shimAt = res.body.indexOf("helix/fetch-shim.js");
    const helperAt = res.body.indexOf("helix/connect-helper.js");
    expect(shimAt).toBeGreaterThanOrEqual(0);
    expect(helperAt).toBeGreaterThan(shimAt); // fetch patched before anything else
    expect(res.body).toContain("window.helix.connect");
  });

  it("an app without the grant serves its bytes untouched (etag preserved)", async () => {
    const res = await serveIndex(
      registryEntry({ appId: "a5", slug: "plain", blobPrefix: "apps/p/1/" }),
    );
    expect(res.body).toBe(HTML);
    expect(res.etag).toBe('"h1"');
  });
});

it("the helper's own exits are members of the shared outcome vocabulary", () => {
  // The helper resolves exactly the message contract's outcome set; its
  // helper-only exits (blocked, cancelled, timeout) are members of it, and so
  // are the bounded reasons it can report itself.
  for (const outcome of ["blocked", "cancelled", "timeout"] as const) {
    expect(CONSENT_MESSAGE_OUTCOMES).toContain(outcome);
  }
  for (const reason of ["provider_unavailable", "service_unavailable", "conflict"] as const) {
    expect(CONSENT_MESSAGE_REASONS).toContain(reason);
  }
});
