import { describe, expect, it } from "vitest";
import { FETCH_ERROR_CODES, FetchErrorCodeSchema, FetchProxyErrorSchema } from "./fetch.js";

/** The pre-delegation vocabulary, in order — the widening may not disturb it. */
const LEGACY_CODES = [
  "forbidden",
  "rate_limited",
  "bad_target",
  "blocked",
  "too_large",
  "replay",
  "upstream_error",
  "upstream_timeout",
] as const;

const DELEGATED_CODES = [
  "connection_required",
  "provider_unavailable",
  "provider_misconfigured",
] as const;

describe("FETCH_ERROR_CODES", () => {
  it("keeps every legacy code, in order, and widens by exactly the three delegated codes", () => {
    expect(FETCH_ERROR_CODES).toEqual([...LEGACY_CODES, ...DELEGATED_CODES]);
  });

  it.each(LEGACY_CODES)("parses the legacy code %s unchanged", (code) => {
    expect(FetchErrorCodeSchema.parse(code)).toBe(code);
  });

  it.each(DELEGATED_CODES)("parses the new delegated code %s", (code) => {
    expect(FetchErrorCodeSchema.parse(code)).toBe(code);
  });

  it("still rejects a code the vocabulary never carried", () => {
    expect(FetchErrorCodeSchema.safeParse("unauthorized").success).toBe(false);
    expect(FetchErrorCodeSchema.safeParse("connection_required ").success).toBe(false);
  });
});

describe("FetchProxyErrorSchema", () => {
  it("round-trips a connection_required body with full provider metadata", () => {
    const body = {
      code: "connection_required",
      message: "connect the provider to call this origin",
      provider: { ref: "asana", displayName: "Asana" },
    };
    expect(FetchProxyErrorSchema.parse(body)).toEqual(body);
  });

  it("parses provider metadata with the displayName omitted (the provider_unavailable shape)", () => {
    const body = {
      code: "provider_unavailable",
      message: "provider is unavailable",
      provider: { ref: "asana" },
    };
    expect(FetchProxyErrorSchema.parse(body)).toEqual(body);
  });

  it("parses without provider metadata — the legacy error shape is unchanged", () => {
    const body = { code: "upstream_error", message: "fetch failed" };
    expect(FetchProxyErrorSchema.parse(body)).toEqual(body);
  });

  it("rejects credential-shaped fields smuggled into the provider metadata", () => {
    const smuggled = [
      { ref: "asana", accessToken: "eyJhbGciOi" },
      { ref: "asana", client_secret: "s3cr3t" },
      { ref: "asana", refresh_token: "rt" },
      { ref: "asana", idToken: "x" },
      { ref: "asana", password: "hunter2" },
      { ref: "asana", authorization: "Bearer x" },
    ];
    for (const provider of smuggled) {
      expect(
        FetchProxyErrorSchema.safeParse({ code: "connection_required", message: "m", provider })
          .success,
        `expected ${JSON.stringify(Object.keys(provider))} to be rejected`,
      ).toBe(false);
    }
  });

  it("rejects metadata without a ref, or with a ref that is not a provider ref", () => {
    expect(
      FetchProxyErrorSchema.safeParse({
        code: "connection_required",
        message: "m",
        provider: { displayName: "Asana" },
      }).success,
    ).toBe(false);
    expect(
      FetchProxyErrorSchema.safeParse({
        code: "connection_required",
        message: "m",
        provider: { ref: "Asana Inc" },
      }).success,
    ).toBe(false);
  });
});
