# Portal database. The portal owns the Postgres schema and every Prisma
# migration; the edge only reads a projection of it.

set working-directory := ".."

[private]
default:
    @just --list --unsorted --justfile {{ source_file() }}

# Create and apply a migration from schema changes (dev); arguments go to `prisma migrate dev`, e.g. --name add_x
[positional-arguments]
migrate *args:
    pnpm --filter @azx-pbc/portal db:migrate "$@"

# Apply pending migrations without creating new ones
deploy:
    pnpm --filter @azx-pbc/portal db:deploy

# Drop the dev database, then re-create it and apply every migration
[confirm('Drop and re-create the dev database? This deletes all local data. [y/N]')]
reset:
    pnpm --filter @azx-pbc/portal db:reset

# Regenerate the Prisma client into apps/portal/src/db/generated
generate:
    pnpm --filter @azx-pbc/portal db:generate

# Seed the platform LLM vendor secret from EDGE_LLM_ANTHROPIC_KEY; arguments go to the seed script, e.g. --force
[positional-arguments]
seed-llm *args:
    pnpm --filter @azx-pbc/portal seed:llm -- "$@"

# Download the DB-IP City Lite database for the portal's Visitors view
geo-fetch:
    pnpm --filter @azx-pbc/portal geo:fetch

# Create and migrate an isolated stack's database, e.g. postgresql://helix:helix@db:5432/helix_smoke
[positional-arguments]
ensure owner-dsn:
    node scripts/ensure-db.mjs "$1"
