#!/usr/bin/env just --justfile
# Helix task runner. Recipes name the pnpm scripts and repo scripts so they are
# discoverable in one place. `./check-and-lint.sh` stays the gate: CI calls it by
# filename, and `just check` calls the same script.

[doc('Dev servers for the three planes, the local IdP, and the SPA')]
mod dev '.justfiles/dev.just'

[doc('Quality gate (wraps ./check-and-lint.sh); `just check` runs all of it')]
mod check '.justfiles/check.just'

[doc('Portal database: Prisma migrations, client generation, seeds')]
mod db '.justfiles/db.just'

[doc('helix CLI (packages/cli): run from source, build, pack')]
mod cli '.justfiles/cli.just'

[doc('Container images, built the way the CI images job builds them')]
mod image '.justfiles/image.just'

[doc('Bicep templates under infra/')]
mod infra '.justfiles/infra.just'

[private]
default:
    @just --list --unsorted

# Install workspace dependencies from the lockfile
install:
    pnpm install --frozen-lockfile
