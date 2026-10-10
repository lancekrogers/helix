#!/usr/bin/env bash
set -euo pipefail

echo "── Fixing volume ownership ──"
# Named-volume mountpoints are created root-owned by Docker; hand them to node.
sudo chown "$(id -u):$(id -g)" \
  /workspace/node_modules \
  /home/node/.pnpm-store \
  /home/node/.cache/ms-playwright \
  /home/node/.codex \
  /home/node/.config \
  /home/node/.config/opencode \
  /home/node/.local/share/opencode \
  /home/node/.pi \
  /home/node/.pi/agent
sudo chown -R "$(id -u):$(id -g)" /home/node/.claude

echo "── Initializing Claude config ──"
# Keep .claude.json inside the named volume so it survives rebuilds, then
# symlink it to the home path Claude Code expects.
if [ ! -f ~/.claude/.claude.json ]; then
  echo '{}' > ~/.claude/.claude.json
fi
ln -sf ~/.claude/.claude.json ~/.claude.json

echo "── Configuring pnpm store ──"
# corepack is enabled at image build (Dockerfile); just point the store at the
# named volume. PATH tweak so pnpm's global-bin check doesn't abort the write.
export PATH="/home/node/.local/share/pnpm/bin:$PATH"
pnpm config set store-dir /home/node/.pnpm-store --global

echo "── Installing Playwright system deps ──"
sudo env "PATH=$PATH" npx -y playwright@latest install-deps chromium

echo "── Generating local TLS certs (mkcert) ──"
# Wildcard cert for *.local.helix.azxlabs.io so the edge can terminate TLS in dev —
# __Host- cookies demand Secure (project plan §3). Idempotent; gitignored.
# NODE_EXTRA_CA_CERTS (compose) makes Node trust the CA in-container. On the
# HOST, import certs/caroot/rootCA.pem into the OS trust store:
#
#   CAROOT=<repo>/.devcontainer/certs/caroot mkcert -install
#
# This is optional for most work — clicking through the browser warning is fine.
# It is NOT optional for the offline capability (ADR-0035): a service worker
# needs a secure context, and a click-through exception does not create one
# (Chromium: "An SSL certificate error occurred when fetching the script"). Fully
# quit the browser afterwards; Chromium caches trust per-process. Regenerating
# the CA (a container rebuild with certs/ cleared) means re-importing.
CERT_DIR=/workspace/.devcontainer/certs
export CAROOT="$CERT_DIR/caroot"
if [ ! -f "$CERT_DIR/local-helix.pem" ] && command -v mkcert >/dev/null; then
  mkdir -p "$CAROOT"
  mkcert -cert-file "$CERT_DIR/local-helix.pem" \
         -key-file "$CERT_DIR/local-helix-key.pem" \
         "*.local.helix.azxlabs.io" local.helix.azxlabs.io
fi

# Split-domain dev (HELIX_APPS_DOMAIN): one cert for the control domain and both
# candidate apps domains. A TLS wildcard covers a single label, so the same-site
# fallback pair (apps.local.helix.azxlabs.io) needs its own wildcard SAN.
if [ ! -f "$CERT_DIR/local-helix-split.pem" ] && command -v mkcert >/dev/null; then
  mkdir -p "$CAROOT"
  mkcert -cert-file "$CERT_DIR/local-helix-split.pem" \
         -key-file "$CERT_DIR/local-helix-split-key.pem" \
         "*.local.helix.azxlabs.io" local.helix.azxlabs.io \
         "*.helix-apps.localhost" helix-apps.localhost \
         "*.apps.local.helix.azxlabs.io" apps.local.helix.azxlabs.io
fi

# ── Dev secret-store KEK ──
# The portal seals connection secrets under this key; egress opens them
# (DEV_SECRETS_KEK_FILE, docker-compose). Generated ONCE here — not at process
# boot — so the portal and egress can never race to create it. Gitignored (lives
# in the certs dir). Prod uses Key Vault instead and leaves this unset.
mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_DIR/secrets-kek.dev" ]; then
  echo "── Generating dev secret-store KEK ──"
  openssl rand -hex 32 > "$CERT_DIR/secrets-kek.dev"
  chmod 600 "$CERT_DIR/secrets-kek.dev"
fi

# ── Workspace install (guarded) ──
# The monorepo isn't scaffolded yet (M0). Only install once a workspace exists.
if [ -f /workspace/package.json ] || [ -f /workspace/pnpm-workspace.yaml ]; then
  echo "── Installing workspace dependencies ──"
  cd /workspace && CI=true pnpm install

  # Geolocation database for the Visitors view (ADR-0050), at the path
  # PORTAL_GEOIP_DB_PATH names in docker-compose.yml. Skipped if already present
  # (it is gitignored, so it survives rebuilds of the same checkout). Non-fatal:
  # without it the portal reports location as unavailable.
  if [ ! -f /workspace/apps/portal/geo/dbip-city-lite.mmdb ]; then
    echo "── Downloading geolocation database (DB-IP City Lite) ──"
    pnpm --filter @azx-pbc/portal geo:fetch \
      || echo "   geo:fetch failed — run 'pnpm --filter @azx-pbc/portal geo:fetch' later"
  fi

  echo "── Pre-caching Playwright browser ──"
  npx -y playwright@latest install chromium
else
  echo "── No workspace package.json yet — skipping pnpm install ──"
fi

echo "── Done! ──"
