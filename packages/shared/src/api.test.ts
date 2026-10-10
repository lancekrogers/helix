import { describe, expect, it } from "vitest";
import {
  ApiErrorSchema,
  CreateAppRequestSchema,
  CreateAppResultSchema,
  UpdateAppRequestSchema,
  UploadVersionResponseSchema,
} from "./api.js";
import { AppSchema } from "./app.js";

describe("CreateAppRequestSchema", () => {
  it("defaults visibility to internal", () => {
    const parsed = CreateAppRequestSchema.parse({ slug: "my-app", displayName: "My App" });
    expect(parsed.visibility).toEqual({ mode: "internal" });
  });

  it("rejects a non-DNS-label slug", () => {
    expect(() => CreateAppRequestSchema.parse({ slug: "Not A Slug", displayName: "x" })).toThrow();
  });

  it("carries an optional description and enforces its cap", () => {
    const parsed = CreateAppRequestSchema.parse({
      slug: "my-app",
      displayName: "My App",
      description: "Tracks Q3 spend by team.",
    });
    expect(parsed.description).toBe("Tracks Q3 spend by team.");
    expect(
      CreateAppRequestSchema.parse({
        slug: "my-app",
        displayName: "x",
        description: "a".repeat(500),
      }).description,
    ).toHaveLength(500);
    expect(() =>
      CreateAppRequestSchema.parse({
        slug: "my-app",
        displayName: "x",
        description: "a".repeat(501),
      }),
    ).toThrow();
  });
});

describe("CreateAppResultSchema", () => {
  const appFields = {
    id: "11111111-1111-4111-8111-111111111111",
    slug: "my-app",
    displayName: "My App",
    visibility: { mode: "internal" as const },
    currentVersionId: null,
    archivedAt: null,
    createdAt: "2026-06-11T00:00:00.000Z",
    updatedAt: "2026-06-11T00:00:00.000Z",
  };

  it("extends the app wire shape with write-gate fields", () => {
    const parsed = CreateAppResultSchema.parse({
      ...appFields,
      applied: [{ path: "llm.models[+gpt-5]", to: "gpt-5" }],
      pending: "aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee",
    });
    expect(parsed.slug).toBe("my-app");
    expect(parsed.applied).toHaveLength(1);
    expect(parsed.pending).toBe("aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee");
  });

  it("parses with AppSchema alone — the published CLI ignores applied and pending", () => {
    const wire = CreateAppResultSchema.parse({
      ...appFields,
      applied: [],
      pending: null,
    });
    const legacy = AppSchema.parse(wire);
    expect(legacy.slug).toBe("my-app");
    expect(legacy).not.toHaveProperty("applied");
    expect(legacy).not.toHaveProperty("pending");
  });
});

describe("UpdateAppRequestSchema", () => {
  it("accepts absent, null and string forms", () => {
    expect(UpdateAppRequestSchema.parse({})).toEqual({});
    expect(UpdateAppRequestSchema.parse({ description: null })).toEqual({ description: null });
    expect(UpdateAppRequestSchema.parse({ description: "Set" })).toEqual({ description: "Set" });
  });

  it("rejects an over-length description", () => {
    expect(() => UpdateAppRequestSchema.parse({ description: "a".repeat(501) })).toThrow();
  });
});

describe("AppSchema description wire compatibility", () => {
  it("omits the key when unset — a response from a portal predating the field parses", () => {
    const app = AppSchema.parse({
      id: "11111111-1111-4111-8111-111111111111",
      slug: "my-app",
      displayName: "My App",
      visibility: { mode: "internal" },
      currentVersionId: null,
      archivedAt: null,
      createdAt: "2026-06-11T00:00:00.000Z",
      updatedAt: "2026-06-11T00:00:00.000Z",
    });
    expect("description" in app).toBe(false);
  });

  it("carries the description when present", () => {
    const app = AppSchema.parse({
      id: "11111111-1111-4111-8111-111111111111",
      slug: "my-app",
      displayName: "My App",
      description: "Tracks Q3 spend by team.",
      visibility: { mode: "internal" },
      currentVersionId: null,
      archivedAt: null,
      createdAt: "2026-06-11T00:00:00.000Z",
      updatedAt: "2026-06-11T00:00:00.000Z",
    });
    expect(app.description).toBe("Tracks Q3 spend by team.");
  });

  it("rejects an over-length description", () => {
    expect(() =>
      AppSchema.parse({
        id: "11111111-1111-4111-8111-111111111111",
        slug: "my-app",
        displayName: "My App",
        description: "a".repeat(501),
        visibility: { mode: "internal" },
        currentVersionId: null,
        archivedAt: null,
        createdAt: "2026-06-11T00:00:00.000Z",
        updatedAt: "2026-06-11T00:00:00.000Z",
      }),
    ).toThrow();
  });
});

describe("UploadVersionResponseSchema", () => {
  it("carries the version and an empty warnings list", () => {
    const parsed = UploadVersionResponseSchema.parse({
      version: {
        id: "22222222-2222-4222-8222-222222222222",
        appId: "11111111-1111-4111-8111-111111111111",
        number: 1,
        blobPrefix: "apps/11111111-1111-4111-8111-111111111111/1/",
        status: "preview",
        createdAt: "2026-06-11T00:00:00.000Z",
      },
      warnings: [],
    });
    expect(parsed.warnings).toEqual([]);
  });
});

describe("ApiErrorSchema", () => {
  it("validates a known error envelope", () => {
    expect(
      ApiErrorSchema.parse({ error: { code: "slug_taken", message: "taken" } }).error.code,
    ).toBe("slug_taken");
  });

  it("rejects an unknown error code", () => {
    expect(() => ApiErrorSchema.parse({ error: { code: "nope", message: "x" } })).toThrow();
  });
});
