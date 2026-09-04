# syntax=docker/dockerfile:1
#
# Multi-stage build, two target profiles:
#   - `slim`       : http + tls fetch tiers only (no headless browser). Small
#                    image, fast cold start. Escalation stops at `tls`.
#   - `autonomous` : full anti-bot stack (+ browser + uc_selenium tiers),
#                    ships Chromium/undetected-chromedriver. Large image.
#
# Build:
#   docker build --target slim       -t kerdoos:slim .
#   docker build --target autonomous -t kerdoos:autonomous .
#
# Phase 7b (ADR 0002 Decision 5): both targets serve the WebUI via the
# create_app() factory. Persistence (config.db/state.db), auth, digest SMTP
# and the egress-proxy are all runtime concerns configured through env vars
# and the /data volume (see the base stage below) -- nothing here is
# deployment-specific.

# Pinned by digest (not just the "3.12-slim" tag) for a reproducible build
# and a closed supply-chain window -- re-resolve with `docker pull
# python:3.12-slim` when bumping.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS base

RUN pip install --no-cache-dir uv==0.10.4

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY packages/autolycos/pyproject.toml packages/autolycos/pyproject.toml
COPY packages/kerdoos/pyproject.toml packages/kerdoos/pyproject.toml
COPY packages/autolycos/src packages/autolycos/src
COPY packages/kerdoos/src packages/kerdoos/src

ENV UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

# ADR 0002 Decision 6: config.db and state.db are two PHYSICALLY separate
# SQLite files behind two abstractions (ConfigStore vs StateStore, invariant
# #7) but share ONE named volume -- the separation is logical (two files),
# not a requirement for two devices. Paths are read from KERDOOS_CONFIG_DB /
# KERDOOS_STATE_DB (kerdoos/config.py); these ENV defaults just point both at
# /data so an operator who only mounts a volume at /data gets a working
# deployment out of the box, still fully overridable via compose/env.
# Non-root user for the slim stage (see USER below) -- created here so a
# named volume mounted at /data inherits this ownership on first init.
RUN useradd -u 10001 -m kerdoos \
    && mkdir -p /data \
    && chown 10001:10001 /data /app
VOLUME ["/data"]
ENV KERDOOS_CONFIG_DB=/data/config.db \
    KERDOOS_STATE_DB=/data/state.db

# --- slim: http + tls tiers, web extra (uvicorn) -----------------------
FROM base AS slim

RUN uv sync --frozen --no-dev --extra web --extra tls

# No browser in this target (escalation stops at tls), so dropping root here
# costs nothing and denies a compromised request handler write access to
# anything but /data. autonomous stays root in this pass (Chromium's own
# sandbox already refuses to run as root, see the `autonomous` stage).
USER 10001

EXPOSE 8000
# Shell form + exec: KERDOOS_WORKERS drives the REAL uvicorn worker count
# (not just the digest evaluator's workers>1 guard-rail), so "N workers +
# the intra-process evaluator both on" is unreachable by construction --
# raising KERDOOS_WORKERS also raises the actual process count, and every
# one of those processes reads the same env var and refuses the evaluator.
CMD exec uvicorn kerdoos.interfaces.web.app:create_app --factory \
    --host 0.0.0.0 --port 8000 --workers ${KERDOOS_WORKERS:-1}

# --- autonomous: + browser + uc_selenium tiers --------------------------
FROM base AS autonomous

RUN uv sync --frozen --no-dev --extra web --extra tls --extra browser --extra uc

# Chromium runtime deps for the browser tier. The browser tier is launched by
# patchright (undetected fork), so install patchright's Chromium (NOT vanilla
# playwright's) here.
RUN uv run patchright install --with-deps chromium

# ADR 0002 Decision 5 (Q-e): pre-fetch the uc tier's undetected chromedriver
# AT BUILD, pinned + checksum-verified, so seleniumbase.Driver(uc=True) never
# needs the download path behind the egress-proxy's strict allowlist at
# runtime (browser_launcher.get_local_driver only re-fetches on a missing
# file or an explicit version mismatch, neither of which applies once this
# exact pinned binary is already on disk).
ARG UC_DRIVER_VERSION=149.0.7827.155
ARG UC_DRIVER_SHA256=5ab28c2e806725ecad5a92cf000988a697c6163eb8d4672bd25d6f37a8e5b7e8
RUN sbase get uc_driver ${UC_DRIVER_VERSION} \
    && echo "${UC_DRIVER_SHA256}  /app/.venv/lib/python3.12/site-packages/seleniumbase/drivers/uc_driver" \
       | sha256sum -c -

EXPOSE 8000
CMD exec uvicorn kerdoos.interfaces.web.app:create_app --factory \
    --host 0.0.0.0 --port 8000 --workers ${KERDOOS_WORKERS:-1}
