# Container images. Recipes build locally with the inputs the CI images job
# uses: the repo root as context, apps/<app>/Dockerfile, and linux/amd64 for
# Azure Container Apps. CI tags and pushes to GHCR; these recipes never push.
#
# On Apple Silicon, set PLATFORM=linux/arm64. An amd64 build under QEMU aborts
# after `pnpm install` with a libuv `uv__io_poll` assertion, so amd64 images
# come from CI or an amd64 builder.

set working-directory := ".."

platform := env("PLATFORM", "linux/amd64")

# CI skips the ~127 MB GeoIP download on PR builds; local builds skip it too
# unless GEOIP_DB_MONTH names a release (YYYY-MM) or is set empty for the latest.
geoip_month := env("GEOIP_DB_MONTH", "skip")

[private]
default:
    @just --list --unsorted --justfile {{ source_file() }}

# Build one image: edge, portal, egress, or certbot. Tagged helix-<app>:<tag>.
[positional-arguments]
build app tag="local":
    #!/usr/bin/env bash
    set -euo pipefail
    app="$1"
    tag="$2"
    if [[ ! -f "apps/${app}/Dockerfile" ]]; then
      echo "unknown app '${app}': expected edge, portal, egress, or certbot" >&2
      exit 2
    fi
    build_args=()
    if [[ "${app}" == "portal" ]]; then
      build_args+=(--build-arg "GEOIP_DB_MONTH={{ geoip_month }}")
    fi
    docker build --platform "{{ platform }}" -f "apps/${app}/Dockerfile" \
      ${build_args[@]+"${build_args[@]}"} -t "helix-${app}:${tag}" .

# Build all four images
build-all tag="local": (build "edge" tag) (build "portal" tag) (build "egress" tag) (build "certbot" tag)
