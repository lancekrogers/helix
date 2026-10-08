# helix CLI (@azx-pbc/helix-cli). Released from a `cli-v*` tag by
# .github/workflows/release-cli.yml; these recipes are for local use.

set working-directory := ".."

[private]
default:
    @just --list --unsorted --justfile {{ source_file() }}

# Run the CLI from source; arguments go to `helix`. It runs in packages/cli, so deploy from an app dir instead.
[positional-arguments]
run *args:
    pnpm --filter @azx-pbc/helix-cli helix -- "$@"

# Bundle the CLI into packages/cli/dist
build:
    pnpm --filter @azx-pbc/helix-cli build

# Build, then pack the tarball as CI does and list its contents
pack: build
    #!/usr/bin/env bash
    set -euo pipefail
    out="$(mktemp -d)/helix-cli.tgz"
    # pnpm pack, not npm pack: only pnpm rewrites catalog: and workspace:
    # specifiers to real version ranges.
    (cd packages/cli && pnpm pack --out "$out")
    tar -tzf "$out"
    echo "packed: $out"
