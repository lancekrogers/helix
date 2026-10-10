import { describe, expect, it } from "vitest";
import { classifyInflightLeasesPrivilege } from "./leaseStore.js";

describe("classifyInflightLeasesPrivilege", () => {
  it("reports ok when the table exists and privileges are granted", () => {
    expect(
      classifyInflightLeasesPrivilege([
        { table_exists: true, can_select: true, can_insert: true, can_delete: true },
      ]),
    ).toEqual({ status: "ok" });
  });

  it("reports misconfigured when the table is missing", () => {
    expect(classifyInflightLeasesPrivilege([])).toMatchObject({ status: "misconfigured" });
    expect(
      classifyInflightLeasesPrivilege([
        { table_exists: false, can_select: false, can_insert: false, can_delete: false },
      ]),
    ).toMatchObject({ status: "misconfigured" });
  });

  it("reports misconfigured when any required privilege is missing", () => {
    expect(
      classifyInflightLeasesPrivilege([
        { table_exists: true, can_select: true, can_insert: true, can_delete: false },
      ]),
    ).toMatchObject({ status: "misconfigured" });
  });
});
