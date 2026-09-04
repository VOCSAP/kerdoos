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

FROM python:3.12-slim AS base

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
RUN mkdir -p /data
VOLUME ["/data"]
ENV KERDOOS_CONFIG_DB=/data/config.db \
    KERDOOS_STATE_DB=/data/state.db

# --- slim: http + tls tiers, web extra (uvicorn) -----------------------
FROM base AS slim

RUN uv sync --frozen --no-dev --extra web --extra tls

EXPOSE 8000
CMD ["uvicorn", "kerdoos.interfaces.web.app:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000"]

# --- autonomous: + browser + uc_selenium tiers --------------------------
FROM base AS autonomous

RUN uv sync --frozen --no-dev --extra web --extra tls --extra browser --extra uc

# Chromium runtime deps for the browser tier. The browser tier is launched by
# patchright (undetected fork), so install patchright's Chromium (NOT vanilla
# playwright's) here; the uc tier's undetected-chromedriver is fetched by
# seleniumbase at runtime.
RUN uv run patchright install --with-deps chromium

EXPOSE 8000
CMD ["uvicorn", "kerdoos.interfaces.web.app:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000"]
