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
# ADR 0002 Decision 5: both targets serve the WebUI via the create_app()
# factory. Persistence (config.db/state.db), auth, digest SMTP and the
# egress-proxy are all runtime concerns configured through env vars and the
# /data volume (see the base stage below) -- nothing here is
# deployment-specific.

# Pinned by digest AND platform (a digest alone still resolves a multi-arch
# index, not one architecture) for a reproducible build and a closed
# supply-chain window -- re-resolve with `docker pull python:3.12-slim` when
# bumping.
FROM --platform=linux/amd64 python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS base

RUN pip install --no-cache-dir uv==0.10.4

# tini as PID 1 reaps orphaned zombie children regardless of the runtime
# orchestrator (docker run, podman, k8s) -- unlike compose's own `init: true`,
# which only applies under `docker compose up` (roadmap d8b7b8fd F1).
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*
# -s: register tini as a subreaper explicitly, so it keeps reaping orphaned
# descendants (not just direct children) even if an operator later adds
# --init/init: true on top of an image whose own PID 1 is already tini.
ENTRYPOINT ["/usr/bin/tini", "-s", "--"]

WORKDIR /app

# Manifests only in this layer (no src/ yet) so the dependency-download layer
# each child stage builds below stays cached across source-code edits.
COPY pyproject.toml uv.lock ./
COPY packages/autolycos/pyproject.toml packages/autolycos/pyproject.toml
COPY packages/kerdoos/pyproject.toml packages/kerdoos/pyproject.toml

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
# named volume mounted at /data inherits this ownership on first init. Only
# /data is chowned: nothing else in the image needs to be writable by it.
RUN useradd -u 10001 -m kerdoos \
    && mkdir -p /data \
    && chown 10001:10001 /data
VOLUME ["/data"]
ENV KERDOOS_CONFIG_DB=/data/config.db \
    KERDOOS_STATE_DB=/data/state.db \
    KERDOOS_DIGEST_EVALUATOR_ENABLED=true

# --no-proxy-headers when KERDOOS_FORWARDED_ALLOW_IPS is empty, rather than
# omitting the flag: uvicorn would otherwise still trust 127.0.0.1 and any
# FORWARDED_ALLOW_IPS present in the environment, letting a forged
# X-Forwarded-For through.
EXPOSE 8000

# Shell form + exec: KERDOOS_WORKERS drives the REAL uvicorn worker count
# (not just the digest evaluator's workers>1 guard-rail), so "N workers +
# the intra-process evaluator both on" is unreachable by construction --
# raising KERDOOS_WORKERS also raises the actual process count, and every
# one of those processes reads the same env var and refuses the evaluator.
# tini (ENTRYPOINT) is PID 1 and relays SIGTERM to uvicorn; `exec` makes
# uvicorn tini's direct child instead of an idle shell's. The value is
# validated (falls back to 1 on empty/non-numeric input, clamped to 32) --
# an unquoted `${VAR:-1}` word-splits on whitespace, and an unclamped huge
# value forks enough processes to take the host down, typo or not.
# Both targets inherit this CMD unchanged; do not duplicate it per stage.
CMD case "$KERDOOS_WORKERS" in \
      ''|*[!0-9]*) W=1 ;; \
      *) W="$KERDOOS_WORKERS"; [ "$W" -gt 32 ] && W=32 ;; \
    esac; \
    if [ -n "$KERDOOS_FORWARDED_ALLOW_IPS" ]; then \
      set -- --proxy-headers --forwarded-allow-ips "$KERDOOS_FORWARDED_ALLOW_IPS"; \
    else \
      set -- --no-proxy-headers; \
    fi; \
    exec uvicorn kerdoos.interfaces.web.app:create_app --factory \
      --host 0.0.0.0 --port 8000 --workers "$W" "$@"

# --- slim: http + tls tiers, web extra (uvicorn) -----------------------
FROM base AS slim

RUN uv sync --frozen --no-dev --no-install-project --extra web --extra tls
COPY packages/autolycos/src packages/autolycos/src
COPY packages/kerdoos/src packages/kerdoos/src
RUN uv sync --frozen --no-dev --extra web --extra tls

# No browser in this target (escalation stops at tls), so dropping root here
# costs nothing. autonomous stays root: MEASURED that patchright's Chromium
# launches fine as root without --no-sandbox in this image (no evidence it
# requires non-root), so dropping root there is a separate, untested change
# (Chromium cache dirs, seleniumbase's driver-patching, Xvfb) deferred to its
# own pass rather than bundled in here.
USER 10001

# --- autonomous: + browser + uc_selenium tiers --------------------------
FROM base AS autonomous

RUN uv sync --frozen --no-dev --no-install-project --extra web --extra tls --extra browser --extra uc

# Both of these are pure tool/environment setup with zero dependency on our
# source code -- placed BEFORE the src COPY (unlike the plain deps sync
# above, Docker layer caching is strictly sequential, so a step placed AFTER
# a source copy re-runs on every source edit regardless of what it actually
# depends on) so a code change never re-downloads Chromium or the driver.
#
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
#
# TOFU, not provenance: Chrome for Testing publishes no signature or
# checksum manifest for these artifacts (checked against their official
# JSON feed), so this hash is trust-on-first-use, captured by us, not
# verified against a third party. To let a future maintainer replay the
# capture: fetched from
# https://storage.googleapis.com/chrome-for-testing-public/149.0.7827.155/linux64/chromedriver-linux64.zip
# on linux/amd64 -- capture context is in the commit that introduced this
# hash, not repeated here (would drift out of sync with a future re-pin).
ARG UC_DRIVER_VERSION=149.0.7827.155
ARG UC_DRIVER_SHA256=5ab28c2e806725ecad5a92cf000988a697c6163eb8d4672bd25d6f37a8e5b7e8
RUN sbase get uc_driver ${UC_DRIVER_VERSION} \
    && echo "${UC_DRIVER_SHA256}  /app/.venv/lib/python3.12/site-packages/seleniumbase/drivers/uc_driver" \
       | sha256sum -c -

# SeleniumBase's own HeadlessChrome UA-spoofing mechanism (get_local_driver's
# uc_agent_cache, triggered whenever headless=True) launches a throwaway
# session through a PLAIN "chromedriver" binary, distinct from "uc_driver"
# above -- without it present, that mechanism silently downloads one from the
# network on first launch (same CWE-494 this stage's uc_driver pin closes,
# just a second file). Reusing the already-verified uc_driver bytes -- rather
# than a second `sbase get` -- means one artifact, one hash, no drift risk
# between the two files.
RUN cp -p /app/.venv/lib/python3.12/site-packages/seleniumbase/drivers/uc_driver \
          /app/.venv/lib/python3.12/site-packages/seleniumbase/drivers/chromedriver

COPY packages/autolycos/src packages/autolycos/src
COPY packages/kerdoos/src packages/kerdoos/src
RUN uv sync --frozen --no-dev --extra web --extra tls --extra browser --extra uc

# ADR 0002 Decision 5: patchright's Chromium and seleniumbase's uc_driver are
# fetched independently above and can drift apart silently into the CWE-494
# path Decision 5 closed (get_local_driver only re-fetches on a version
# MISMATCH, behind the egress-proxy's strict allowlist). Assert their major
# versions match at BUILD time, through UcFetcher's own runtime resolver.
# LAST instruction of this stage on purpose: it must run under the stage's
# FINAL effective user, so it stays HOME-sensitive to any future USER change.
# Bare redeclare (no new default): keeps the ARG from Decision 5 above in
# scope for this instruction's shell substitution.
ARG UC_DRIVER_SHA256
RUN set -eu; \
    CHROME_BIN=$(python3 -c \
      "from autolycos.adapters.uc import _find_patchright_chromium as f; print(f() or '')"); \
    if [ -z "$CHROME_BIN" ]; then \
      echo "BUILD FAIL: _find_patchright_chromium() found no Chromium under \$HOME/.cache/ms-playwright" >&2; \
      exit 1; \
    fi; \
    CHROME_VER=$("$CHROME_BIN" --version --no-sandbox | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'); \
    UC_DRIVER_BIN=/app/.venv/lib/python3.12/site-packages/seleniumbase/drivers/uc_driver; \
    UC_VER=$("$UC_DRIVER_BIN" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'); \
    CHROMEDRIVER_BIN=/app/.venv/lib/python3.12/site-packages/seleniumbase/drivers/chromedriver; \
    CHROMEDRIVER_VER=$("$CHROMEDRIVER_BIN" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'); \
    CHROME_MAJOR=${CHROME_VER%%.*}; \
    UC_MAJOR=${UC_VER%%.*}; \
    CHROMEDRIVER_MAJOR=${CHROMEDRIVER_VER%%.*}; \
    if [ "$CHROME_MAJOR" != "$UC_MAJOR" ]; then \
      echo "BUILD FAIL: chromium major $CHROME_MAJOR (patchright, $CHROME_VER) != uc_driver major $UC_MAJOR (UC_DRIVER_VERSION pin, $UC_VER) -- re-pin UC_DRIVER_VERSION/UC_DRIVER_SHA256 to patchright's Chromium major (ADR 0002 Decision 5)." >&2; \
      exit 1; \
    fi; \
    if [ "$CHROME_MAJOR" != "$CHROMEDRIVER_MAJOR" ]; then \
      echo "BUILD FAIL: chromium major $CHROME_MAJOR (patchright, $CHROME_VER) != chromedriver major $CHROMEDRIVER_MAJOR ($CHROMEDRIVER_VER) -- the copied chromedriver drifted from uc_driver (ADR 0002 Decision 5)." >&2; \
      exit 1; \
    fi; \
    echo "${UC_DRIVER_SHA256}  $UC_DRIVER_BIN" | sha256sum -c -; \
    echo "${UC_DRIVER_SHA256}  $CHROMEDRIVER_BIN" | sha256sum -c -; \
    echo "OK: chromium major $CHROME_MAJOR matches uc_driver major $UC_MAJOR and chromedriver major $CHROMEDRIVER_MAJOR, both sha256-verified on final bytes"
