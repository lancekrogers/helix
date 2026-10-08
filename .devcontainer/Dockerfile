# TypeScript/Node monorepo dev image. The MS typescript-node base ships Node 24,
# npm, git, zsh + oh-my-zsh, and a non-root `node` user (uid 1000) with sudo.
FROM mcr.microsoft.com/devcontainers/typescript-node:24-bookworm

# ── System packages ──────────────────────────────────────────
# postgresql-client → psql/pg_isready against the db service.
# mkcert → local wildcard TLS cert for *.local.helix.azxlabs.io (M3: __Host- cookies
# demand Secure, so the edge terminates TLS in dev; see post-create.sh).
# shellcheck → the same lint CI runs over scripts/ (shellcheck job).
RUN apt-get update && apt-get install -y --no-install-recommends \
        postgresql-client jq fzf vim less mkcert ripgrep shellcheck openssh-server mosh \
    && rm -rf /var/lib/apt/lists/*

# ── actionlint (pinned; apt doesn't carry it) ────────────────
# The workflow lint half of CI parity — runs .github/workflows/*.yml with
# -shellcheck=shellcheck. The project's own script verifies the release
# checksum; install to /usr/local/bin while still root.
RUN curl -fsSL https://raw.githubusercontent.com/rhysd/actionlint/v1.7.7/scripts/download-actionlint.bash \
        | bash -s -- 1.7.7 /usr/local/bin

# ── just (pinned; bookworm's apt doesn't carry it) ───────────
# Runs the root justfile. The release tarball is checked against the
# SHA256SUMS file published with the same release before it is unpacked.
ARG JUST_VERSION=1.58.0
RUN set -eu; \
    arch="$(uname -m)"; \
    case "${arch}" in x86_64 | aarch64) ;; *) echo "just: unsupported arch ${arch}" >&2; exit 1 ;; esac; \
    tarball="just-${JUST_VERSION}-${arch}-unknown-linux-musl.tar.gz"; \
    base="https://github.com/casey/just/releases/download/${JUST_VERSION}"; \
    tmp="$(mktemp -d)"; \
    curl -fsSL -o "${tmp}/${tarball}" "${base}/${tarball}"; \
    curl -fsSL -o "${tmp}/SHA256SUMS" "${base}/SHA256SUMS"; \
    (cd "${tmp}" && grep " ${tarball}\$" SHA256SUMS | sha256sum -c -); \
    tar -xzf "${tmp}/${tarball}" -C /usr/local/bin just; \
    rm -rf "${tmp}"; \
    just --version

# ── gh CLI ───────────────────────────────────────────────────
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# ── Azure CLI ────────────────────────────────────────────────
# `infra/azure` is Bicep and is the source of truth for the deployed topology,
# so a template change should be checkable here rather than only at apply time:
# `az bicep build --file infra/azure/main.bicep` compiles and lints it, and
# `az deployment group what-if` previews against a live subscription. Also the
# tool the runbooks in docs/runbooks/ tell an operator to run.
RUN curl -fsSL https://aka.ms/InstallAzureCLIDeb | bash \
    && rm -rf /var/lib/apt/lists/*

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0

COPY --from=devcontainer sshd_config /etc/ssh/helix_sshd_config
COPY --from=devcontainer start-remote.sh /usr/local/bin/helix-start-remote
RUN chmod 755 /usr/local/bin/helix-start-remote

# ── pnpm via corepack ────────────────────────────────────────
# Enable as root so the shims land in /usr/local/bin (root-owned). Doing this
# in post-create would fail with EACCES since that runs as `node`.
RUN corepack enable pnpm

# ── Everything below runs as the unprivileged `node` user ────
USER node

# Remote terminal tools; their state is persisted separately in Compose.
RUN curl -fsSL https://herdr.dev/install.sh | sh
RUN curl -fsSL https://getmoshi.app/install.sh \
    | MOSHI_HOOK_SKIP_SERVICE=1 MOSHI_HOOK_SKIP_FIRST_RUN=1 sh

# ── Coding agents ────────────────────────────────────────────
# Claude Code via the native installer (no Node dependency); codex + opencode
# as global npm packages. Their *configs* live in named volumes (see compose),
# so logins survive rebuilds; the binaries are baked into the image.
RUN curl -fsSL https://claude.ai/install.sh | bash
RUN npm install -g @openai/codex opencode-ai
# pi (pi.dev), same npm route but with --ignore-scripts as its install docs
# prescribe; its whole agent dir (~/.pi/agent — settings, auth, sessions) is
# one named volume in compose.
RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent

# claude installs to ~/.local/bin
RUN echo 'export PATH="$HOME/.local/bin:$PATH"' >> /home/node/.zshrc \
    && echo 'export PATH="$HOME/.local/bin:$PATH"' >> /home/node/.bashrc

# SSH drops the container environment. Load only the project variables exported
# by the startup script, including for non-interactive agent discovery.
RUN for rc in .bashrc .zshenv; do \
        touch "/home/node/$rc"; \
        sed -i '1i [ ! -r /run/helix-remote-env ] || . /run/helix-remote-env' "/home/node/$rc"; \
    done

WORKDIR /workspace
