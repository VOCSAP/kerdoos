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
# Structural skeleton only (Phase 0, ADR 0001 §7): no auth, no digest SMTP
# wiring, no SQLite ConfigStore, no egress-proxy. Runs the WebUI /health
# endpoint via the create_app() factory.

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

# --- slim: http + tls tiers, web extra (uvicorn) -----------------------
FROM base AS slim

RUN uv sync --frozen --no-dev --extra web --extra tls

EXPOSE 8000
CMD ["uvicorn", "kerdoos.interfaces.web.app:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000"]

# --- autonomous: + browser + uc_selenium tiers --------------------------
FROM base AS autonomous

RUN uv sync --frozen --no-dev --extra web --extra tls --extra browser --extra uc

# Chromium runtime deps for playwright + seleniumbase UC.
RUN uv run playwright install --with-deps chromium

EXPOSE 8000
CMD ["uvicorn", "kerdoos.interfaces.web.app:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000"]
