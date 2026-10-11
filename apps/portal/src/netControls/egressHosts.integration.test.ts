import { afterAll, describe, expect, it } from "vitest";
import { collectNeededHosts } from "./egressHosts.js";
import { createTestPrisma, uniqueSlug } from "../test/harness.js";

const prisma = createTestPrisma();
const createdSlugs: string[] = [];
const createdProviderIds: string[] = [];

afterAll(async () => {
  if (createdProviderIds.length > 0) {
    await prisma.connectionProvider.deleteMany({
      where: { id: { in: createdProviderIds } },
    });
  }
  if (createdSlugs.length > 0) {
    await prisma.app.deleteMany({ where: { slug: { in: createdSlugs } } });
  }
  await prisma.$disconnect();
});

describe("collectNeededHosts", () => {
  it("reads live apps and prod providers from the database", async () => {
    const activeSlug = uniqueSlug("egress-hosts");
    const archivedSlug = uniqueSlug("egress-arch");
    createdSlugs.push(activeSlug, archivedSlug);

    await prisma.app.create({
      data: {
        slug: activeSlug,
        displayName: "Egress hosts active",
        ownerId: "test-owner",
        visibilityMode: "internal",
        visibilityGroupIds: [],
        capabilities: {
          fetch: {
            origins: [{ origin: "https://active-origin.example.com/path" }],
          },
        },
      },
    });
    await prisma.app.create({
      data: {
        slug: archivedSlug,
        displayName: "Egress hosts archived",
        ownerId: "test-owner",
        visibilityMode: "internal",
        visibilityGroupIds: [],
        archivedAt: new Date(),
        capabilities: {
          fetch: {
            origins: [{ origin: "https://archived-origin.example.com" }],
          },
        },
      },
    });

    const ref = `egress-hosts-${activeSlug}`;
    const provider = await prisma.connectionProvider.create({
      data: {
        ref,
        kind: "rest-delegated",
        displayName: "Egress hosts provider",
        authorizeEndpoint: "https://vendor.example/oauth/authorize",
        tokenEndpoint: "https://token.vendor.example/oauth/token",
        requestedScopes: ["read"],
        apiOrigins: ["https://api.vendor.example"],
        tokenPlacement: { kind: "header-bearer" },
        env: "prod",
        clientIdMaterial: "sealed:test",
        clientSecretMaterial: "sealed:test",
      },
    });
    createdProviderIds.push(provider.id);

    const { needs, unparseable } = await collectNeededHosts(prisma);
    expect(unparseable).toEqual([]);

    const active = needs.find((n) => n.host === "active-origin.example.com");
    expect(active?.sources).toContain(`app:${activeSlug}`);
    expect(needs.some((n) => n.host === "archived-origin.example.com")).toBe(false);

    const token = needs.find((n) => n.host === "token.vendor.example");
    expect(token?.sources).toContain(`provider:${ref}`);
    const api = needs.find((n) => n.host === "api.vendor.example");
    expect(api?.sources).toContain(`provider:${ref}`);
  });
});
