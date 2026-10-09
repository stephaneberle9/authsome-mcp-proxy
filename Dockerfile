# syntax=docker/dockerfile:1@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
#
# Multi-stage build for `authsome-mcp-proxy`. The image is intended primarily
# for the **web connector** deployment (k8s in front of ANALYZE / SECURE /
# similar token-validating MCP servers), so the production stage defaults to
# `--transport http` bound to `0.0.0.0:8000` and exposes port 8000.
# Operators can override any of those via container env vars (k8s deployment
# manifest, `docker run -e ...`, etc.).
#
# Base image: python:3.13-slim pinned by digest for reproducibility.

# ---------------------------------------------------------------------------
# Builder stage
# ---------------------------------------------------------------------------
FROM python:3.13-slim@sha256:a0779d7c12fc20be6ec6b4ddc901a4fd7657b8a6bc9def9d3fde89ed5efe0a3d AS builder

WORKDIR /app

# `uv-dynamic-versioning` reads the latest git tag during `uv sync` to
# derive the project version. `python:3.13-slim` doesn't ship `git`, so
# install it in the builder stage. The production stage doesn't include
# git — only the resolved venv from this stage is carried forward.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Install uv (Astral's Python package manager, our project's standard).
COPY --from=ghcr.io/astral-sh/uv:latest@sha256:3b7b60a81d3c57ef471703e5c83fd4aaa33abcd403596fb22ab07db85ae91347 /uv /uvx /usr/local/bin/

# Dependency manifests + README first so the dependency-resolution layer is
# cache-friendly across source-only changes. README is required by hatchling
# when building the project itself.
COPY pyproject.toml uv.lock README.md ./

# `.git/` is needed by `uv-dynamic-versioning` to derive the project version
# from the latest git tag during `uv sync` (which builds and installs the
# local project). Keeping it in the builder stage only — the final image
# does not include `.git/`.
COPY .git/ ./.git/

# Source tree.
COPY src/ ./src/

# Resolve the locked dependencies and install the project itself into
# /app/.venv. `--no-dev` keeps test/dev tooling out of the production layer;
# `--no-editable` installs the project as a normal wheel (rather than a
# `.pth`-pointer back to src/) so the production stage doesn't need a copy
# of src/ on disk. `--all-extras` bundles every store backend (STORE_BACKEND)
# so the published image can be pointed at any of them by configuration alone;
# the proxy imports a backend's SDK only when it is selected. Build without it
# for a minimal image that only uses the default file store.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --all-extras


# ---------------------------------------------------------------------------
# Production stage
# ---------------------------------------------------------------------------
FROM python:3.13-slim@sha256:a0779d7c12fc20be6ec6b4ddc901a4fd7657b8a6bc9def9d3fde89ed5efe0a3d AS production

# Non-root user — the proxy doesn't need any elevated privileges.
# Numeric UID/GID are pinned so Kubernetes can verify `runAsNonRoot: true`
# at admission time without resolving a name. Named users (e.g. `USER appuser`)
# trip the admission check with "cannot verify user is non-root".
RUN groupadd -r -g 1001 appuser && useradd -r -u 1001 -g appuser appuser

WORKDIR /app

# Only the resolved virtualenv from the builder; no `uv` or source tree
# needed at runtime (the project is installed into the venv).
COPY --from=builder /app/.venv /app/.venv

# HOME=/app: FastMCP's OAuthProxy (parent of AWSCognitoProvider et al.)
# auto-creates a FileTreeStore for its OAuth state -- client registrations and
# users' sessions -- unless STORE_BACKEND selects an external one, at
# `settings.home`, which defaults to `user_data_dir("fastmcp")` →
# `~/.local/share/fastmcp`. `useradd -r` (above) doesn't create
# /home/appuser, so the mkdir fails with `Permission denied: '/home/appuser'`
# at startup. Pointing HOME at /app reuses the already-chown'd WORKDIR
# instead of carrying a second writable home directory.
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    HOME=/app

# Web-mode defaults so the image is k8s-deploy-ready out of the box.
# Override any of these via the container env (k8s deployment manifest or
# `docker run -e ...`) to run in stdio mode or to change the bind address /
# port.
ENV MCP_PROXY_TRANSPORT=http \
    MCP_PROXY_HOST=0.0.0.0 \
    MCP_PROXY_PORT=8000

# Suppress FastMCP's startup PyPI version check -- containerized pods
# shouldn't phone home on every cold start, and the "update available"
# banner is noise in logs. Operators who want it can override with
# "stable" or "prerelease". (FastMCP 3.3.1+ uses a tri-state literal,
# not a boolean -- "false" would be rejected at Settings() validation.)
ENV FASTMCP_CHECK_FOR_UPDATES=off

RUN chown -R 1001:1001 /app
USER 1001

LABEL org.opencontainers.image.source="https://github.com/stephaneberle9/authsome-mcp-proxy"
LABEL org.opencontainers.image.description="Authsome MCP Proxy — bridges upstream MCP servers protected by token validation or static credentials to MCP clients (Claude Desktop, Claude Code, Cursor, Codex, MCP Inspector, Claude.ai)."
LABEL org.opencontainers.image.licenses="Apache-2.0"

EXPOSE 8000

CMD ["authsome-mcp-proxy"]
