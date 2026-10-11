import { describe, expect, it } from "vitest";
import { ReplicaGate } from "./replicaGate.js";

describe("ReplicaGate", () => {
  it("admits up to the limit and refuses the next", () => {
    const gate = new ReplicaGate(2);
    expect(gate.tryEnter()).toBe(true);
    expect(gate.tryEnter()).toBe(true);
    expect(gate.tryEnter()).toBe(false);
  });

  it("leave frees a slot and never goes negative", () => {
    const gate = new ReplicaGate(1);
    expect(gate.tryEnter()).toBe(true);
    expect(gate.tryEnter()).toBe(false);
    gate.leave();
    gate.leave();
    expect(gate.tryEnter()).toBe(true);
  });

  it("0 never refuses", () => {
    const gate = new ReplicaGate(0);
    for (let i = 0; i < 5; i++) {
      expect(gate.tryEnter()).toBe(true);
    }
  });
});
