# Quality gate. Every recipe runs ./check-and-lint.sh with step names, so a
# local `just check` and the CI static and test jobs run the same commands.
# The first recipe is the module default: `just check` runs the full gate.

set working-directory := ".."

# Full gate: typecheck, lint, refs, format, docs, tests
all:
    ./check-and-lint.sh

# Auto-fix lint and formatting, then run the full gate
fix:
    ./check-and-lint.sh --fix

# The static half of the gate, as the CI static job runs it
static:
    ./check-and-lint.sh typecheck lint refs format docs

# Type-check every workspace package
typecheck:
    ./check-and-lint.sh typecheck

# ESLint, including the telemetry and SDK-boundary security rules
lint:
    ./check-and-lint.sh lint

# Scan tracked files for machine-local planning identifiers
refs:
    ./check-and-lint.sh refs

# Prettier check
format:
    ./check-and-lint.sh format

# Build the docs site, which fails on dead internal links
docs:
    ./check-and-lint.sh docs

# Vitest suite (needs Postgres and Azurite); arguments go to Vitest, e.g. --shard=1/3
[positional-arguments]
test *args:
    if [ "$#" -gt 0 ]; then ./check-and-lint.sh test -- "$@"; else ./check-and-lint.sh test; fi

# Vitest in watch mode
watch:
    pnpm test:watch

# Connections browser lane (Playwright under xvfb-run, Linux only), as the CI browser-lane job runs it
lane:
    pnpm lane:connections
