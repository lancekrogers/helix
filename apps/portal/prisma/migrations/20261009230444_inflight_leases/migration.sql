-- CreateTable
CREATE TABLE "inflight_leases" (
    "id" UUID NOT NULL,
    "scope" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "inflight_leases_pkey" PRIMARY KEY ("id","scope")
);

-- CreateIndex
CREATE INDEX "inflight_leases_scope_expiresAt_idx" ON "inflight_leases"("scope", "expiresAt");

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'helix_edge') THEN
    GRANT SELECT, INSERT, DELETE ON inflight_leases TO helix_edge;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'helix_portal') THEN
    -- The blanket grant in db-init/01-roles.sql (and infra/azure/sql/01-roles.sql) gives the
    -- control plane full DML on every owner-created table. It never touches this one.
    REVOKE ALL ON inflight_leases FROM helix_portal;
  END IF;
END $$;
