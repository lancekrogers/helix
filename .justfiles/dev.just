# Dev servers. Each recipe runs the matching `pnpm dev:*` script from the root
# package.json, which frees its port before binding. Run them inside the dev
# container, where the auth, database, and Blob environment is already set.

set working-directory := ".."

[private]
default:
    @just --list --unsorted --justfile {{ source_file() }}

# helix-edge, the data/policy plane (https on :8080)
edge:
    pnpm dev:edge

# Edge dev-gateway for developing apps against the env=dev tier (:8082)
devgw:
    pnpm dev:devgw

# helix-egress, the mechanism plane (:8081)
egress:
    pnpm dev:egress

# helix-portal, the control plane API (:3001)
portal:
    pnpm dev:portal

# Local OIDC issuer standing in for Entra (:3002, dev only)
idp:
    pnpm dev:idp

# Portal SPA dev server (:5173, proxies /api to :3001)
web:
    pnpm dev:web

# Public docs site dev server (VitePress)
docs:
    pnpm dev:docs

# Fixture OAuth vendor for connection testing
vendor:
    pnpm dev:vendor

# HTTPS front for the fixture OAuth vendor
vendor-tls:
    pnpm dev:vendor-tls

# Kill stale listeners on every port this stack uses
clean:
    pnpm dev:clean

# Boot the whole stack, run the end-to-end smoke checks, and shut down; arguments go to the runner, e.g. --no-browser --keep
[positional-arguments]
smoke *args:
    node .claude/skills/run-helix/smoke.mjs "$@"
