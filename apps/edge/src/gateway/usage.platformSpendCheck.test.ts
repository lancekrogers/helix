import { describe, expect, it } from "vitest";
import { classifyPlatformSpendCheck } from "./usage.js";

describe("classifyPlatformSpendCheck", () => {
  it("reports ok when definer and owner policy are present", () => {
    expect(classifyPlatformSpendCheck([{ definer: true, owner_policy: true }])).toEqual({
      status: "ok",
    });
  });

  it("reports misconfigured when the function row is missing", () => {
    expect(classifyPlatformSpendCheck([])).toMatchObject({ status: "misconfigured" });
  });

  it("reports misconfigured when not SECURITY DEFINER", () => {
    expect(classifyPlatformSpendCheck([{ definer: false, owner_policy: true }])).toMatchObject({
      status: "misconfigured",
    });
  });

  it("reports misconfigured when the owner policy does not admit the function owner", () => {
    expect(classifyPlatformSpendCheck([{ definer: true, owner_policy: false }])).toMatchObject({
      status: "misconfigured",
    });
  });
});
