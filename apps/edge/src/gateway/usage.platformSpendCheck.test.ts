import { describe, expect, it } from "vitest";
import { classifyPlatformSpendCheck, type PlatformSpendCheckRow } from "./usage.js";

function okRow(overrides: Partial<PlatformSpendCheckRow> = {}): PlatformSpendCheckRow {
  return {
    fn_name_ok: true,
    security_definer: true,
    search_path_pinned: true,
    policy_name_ok: true,
    policy_cmd_ok: true,
    policy_admits_owner: true,
    ...overrides,
  };
}

describe("classifyPlatformSpendCheck", () => {
  it("reports ok when definer and owner policy are present", () => {
    expect(classifyPlatformSpendCheck([okRow()])).toEqual({
      status: "ok",
    });
  });

  it("reports misconfigured when the function row is missing", () => {
    expect(classifyPlatformSpendCheck([])).toMatchObject({ status: "misconfigured" });
    expect(classifyPlatformSpendCheck([okRow({ fn_name_ok: false })])).toMatchObject({
      status: "misconfigured",
    });
  });

  it("reports misconfigured when not SECURITY DEFINER", () => {
    expect(classifyPlatformSpendCheck([okRow({ security_definer: false })])).toMatchObject({
      status: "misconfigured",
    });
  });

  it("reports misconfigured when search_path is not pinned", () => {
    expect(classifyPlatformSpendCheck([okRow({ search_path_pinned: false })])).toMatchObject({
      status: "misconfigured",
    });
  });

  it("reports misconfigured when the owner policy does not admit the function owner", () => {
    expect(classifyPlatformSpendCheck([okRow({ policy_admits_owner: false })])).toMatchObject({
      status: "misconfigured",
    });
  });
});
