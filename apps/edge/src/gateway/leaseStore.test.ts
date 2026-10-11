import { describe, expect, it } from "vitest";
import { InMemoryLeaseStore } from "./leaseStore.js";

describe("InMemoryLeaseStore", () => {
  it("acquires up to the cap then refuses and names the full scope", async () => {
    const store = new InMemoryLeaseStore(() => 0);
    const scope = "llm:app:a";
    for (let i = 0; i < 3; i++) {
      expect(await store.acquire([{ scope, cap: 3 }], 60_000)).toEqual({
        ok: true,
        leaseId: expect.any(String),
      });
    }
    const denied = await store.acquire([{ scope, cap: 3 }], 60_000);
    expect(denied).toEqual({ ok: false, scope });
  });

  it("all-or-none: a full second scope leaves the first untouched", async () => {
    const store = new InMemoryLeaseStore(() => 0);
    const a = "llm:app:a";
    const b = "llm:app:b";
    await store.acquire([{ scope: b, cap: 1 }], 60_000);
    expect(
      await store.acquire(
        [
          { scope: a, cap: 2 },
          { scope: b, cap: 1 },
        ],
        60_000,
      ),
    ).toEqual({
      ok: false,
      scope: b,
    });
    expect(await store.acquire([{ scope: a, cap: 2 }], 60_000)).toEqual({
      ok: true,
      leaseId: expect.any(String),
    });
    expect(await store.acquire([{ scope: a, cap: 2 }], 60_000)).toEqual({
      ok: true,
      leaseId: expect.any(String),
    });
    expect(await store.acquire([{ scope: a, cap: 2 }], 60_000)).toEqual({ ok: false, scope: a });
  });

  it("release frees a slot", async () => {
    const store = new InMemoryLeaseStore(() => 0);
    const scope = "fetch:app:x";
    const first = await store.acquire([{ scope, cap: 1 }], 60_000);
    expect(first.ok).toBe(true);
    expect(await store.acquire([{ scope, cap: 1 }], 60_000)).toEqual({ ok: false, scope });
    if (first.ok) await store.release(first.leaseId);
    expect(await store.acquire([{ scope, cap: 1 }], 60_000)).toEqual({
      ok: true,
      leaseId: expect.any(String),
    });
  });

  it("an expired lease frees its slot without sweep", async () => {
    let now = 0;
    const store = new InMemoryLeaseStore(() => now);
    const scope = "llm:user:app:u";
    await store.acquire([{ scope, cap: 1 }], 100);
    now = 101;
    expect(await store.acquire([{ scope, cap: 1 }], 60_000)).toEqual({
      ok: true,
      leaseId: expect.any(String),
    });
  });

  it("sweep removes expired entries only", async () => {
    let now = 0;
    const store = new InMemoryLeaseStore(() => now);
    const live = "llm:app:live";
    const dead = "llm:app:dead";
    await store.acquire([{ scope: live, cap: 5 }], 10_000);
    await store.acquire([{ scope: dead, cap: 5 }], 50);
    now = 100;
    await store.sweep();
    expect(await store.acquire([{ scope: dead, cap: 1 }], 60_000)).toEqual({
      ok: true,
      leaseId: expect.any(String),
    });
    expect(await store.acquire([{ scope: live, cap: 1 }], 60_000)).toEqual({
      ok: false,
      scope: live,
    });
  });

  it("cap <= 0 skips the scope", async () => {
    const store = new InMemoryLeaseStore(() => 0);
    const scope = "llm:app:uncapped";
    const r = await store.acquire([{ scope, cap: 0 }], 60_000);
    expect(r.ok).toBe(true);
    expect(await store.acquire([{ scope, cap: 1 }], 60_000)).toEqual({
      ok: true,
      leaseId: expect.any(String),
    });
  });

  it("deduplicates scopes in one call (keeps smallest cap)", async () => {
    const store = new InMemoryLeaseStore(() => 0);
    const scope = "llm:app:dup";
    await store.acquire(
      [
        { scope, cap: 2 },
        { scope, cap: 5 },
      ],
      60_000,
    );
    await store.acquire(
      [
        { scope, cap: 5 },
        { scope, cap: 2 },
      ],
      60_000,
    );
    expect(await store.acquire([{ scope, cap: 2 }], 60_000)).toEqual({ ok: false, scope });
  });

  it("releasing an unknown id is a no-op", async () => {
    const store = new InMemoryLeaseStore(() => 0);
    await expect(store.release("00000000-0000-0000-0000-000000000000")).resolves.toBeUndefined();
  });

  it("only uncapped scopes returns a lease id and holds nothing", async () => {
    const store = new InMemoryLeaseStore(() => 0);
    const r = await store.acquire(
      [
        { scope: "llm:app:a", cap: -1 },
        { scope: "llm:app:b", cap: 0 },
      ],
      60_000,
    );
    expect(r.ok).toBe(true);
    expect(await store.acquire([{ scope: "llm:app:a", cap: 1 }], 60_000)).toEqual({
      ok: true,
      leaseId: expect.any(String),
    });
  });
});
