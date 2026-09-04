# INSTALL_FOR_AI.md

Minimal, verified steps to install and run Kerdoos. This file is about
*installing and launching*; for invariants, conventions, and contribution
discipline see `AGENTS.md`.

## Prerequisites

- Python >= 3.11 (`packages/kerdoos/pyproject.toml`, `packages/autolycos/pyproject.toml`).
- [`uv`](https://docs.astral.sh/uv/) as the dependency and workspace manager.

## Install

```bash
uv sync
```

This resolves the `uv` workspace (`packages/*`, declared in the root
`pyproject.toml`) and installs both packages (`kerdoos`, `autolycos`) plus
the `dev` dependency group (`pytest`, `httpx`).

The WebUI needs the optional `web` extra (installs `uvicorn`):

```bash
uv sync --extra web
```

Anti-bot fetch tiers beyond `http` are also optional extras on `autolycos`
(`tls`, `browser`, `uc`) -- add them only if you need that escalation tier
locally; the Docker images (see below) wire them per profile.

## Run the CLI

The composition root is `packages/kerdoos/src/kerdoos/interfaces/cli/main.py`.
On `main` today (no installed `kerdoos` console script yet -- see note below),
invoke it as a module:

```bash
uv run python -m kerdoos.interfaces.cli --help
```

Subcommands (from `build_parser_cli` in the same file):

- `run --owner <id> [--config-db config.db] [--db kerdoos.db] [--dry-run]` --
  scrape every configured source for one owner and print the digest.
- `digest [--config-db config.db] [--db kerdoos.db]` -- run one digest-jobs
  evaluation tick across all owners, then exit (for external cron when
  `KERDOOS_WORKERS > 1`).
- `config import [--config-dir config] [--config-db config.db] [--db kerdoos.db] [--owner <id>]`
  -- upsert `sites.yaml` (and `products.yaml` if `--owner` is given) into `config.db`.
- `config export [--config-dir config] [--config-db config.db] [--owner <id>]`
  -- write `config.db` back out to `sites.yaml`/`products.yaml`.
- `user bootstrap --name <name> [--config-db config.db] [--admin]` -- create a
  minimal owner row (no password).
- `user add --name <name> [--email <email>] [--config-db config.db] [--admin]`
  -- create an owner with a password (prompted, never passed as an argument).

Example config/site and product definitions to import live in
`config/sites.yaml` and `config/products.yaml`; copy
`config/kerdoos.yaml.example` as a starting point for a real deployment
config.

> Note: `[project.scripts] kerdoos` (a `kerdoos` console-script entrypoint)
> exists on the unmerged `phase7b-packaging` branch, not yet on `main`. Once
> merged, `uv run kerdoos --help` will work directly; until then use the
> `python -m kerdoos.interfaces.cli` form above.

## Run the WebUI

The WebUI is a FastAPI app built by the `create_app()` factory
(`packages/kerdoos/src/kerdoos/interfaces/web/app.py`):

```bash
uv run --extra web uvicorn kerdoos.interfaces.web.app:create_app --factory --host 0.0.0.0 --port 8000
```

`KERDOOS_SESSION_SECRET` is required (see Environment variables below); the
app refuses to start without it.

## Environment variables

All are read lazily by `get_settings()` in `packages/kerdoos/src/kerdoos/config.py`.
None have a hardcoded infrastructure default; the SMTP relay is entirely
operator-configured.

| Variable | Default | Purpose |
|---|---|---|
| `KERDOOS_SESSION_SECRET` | none (required for the WebUI) | HMAC key for signed session cookies. Must be >= 32 characters. |
| `KERDOOS_CONFIG_DB` | `config.db` | SQLite `ConfigStore` path. |
| `KERDOOS_STATE_DB` | `state.db` | SQLite `StateStore` path. |
| `KERDOOS_COOKIE_SECURE` | `true` | Set the session cookie's `Secure` flag; set `false` for a plain-HTTP LAN deployment. |
| `KERDOOS_WORKERS` | `1` | Process count the operator has deployed; gates the digest evaluator's `workers>1` guard-rail. |
| `KERDOOS_DIGEST_EVALUATOR_ENABLED` | `false` | Opt-in switch for the WebUI's intra-process digest evaluator lifespan task. |
| `KERDOOS_SMTP_HOST` | none | SMTP relay host. Digest mail falls back to a log-only sender until this is set. |
| `KERDOOS_SMTP_PORT` | `587` | SMTP port (only applied once `KERDOOS_SMTP_HOST` is set). |
| `KERDOOS_SMTP_FROM` | none | Envelope `From` address. |
| `KERDOOS_SMTP_USERNAME` | none | SMTP auth username. |
| `KERDOOS_SMTP_PASSWORD` | none | SMTP auth password. |
| `KERDOOS_SMTP_USE_TLS` | `true` | Use STARTTLS. |
| `KERDOOS_SMTP_TIMEOUT_SECONDS` | `30` | Socket timeout for the SMTP connection; must stay below the reaper timeout. |
| `KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS` | `300` | Max-send-timeout bound the evaluator's reaper uses to reclaim a stranded `job_runs` row. |

## Where the databases live

Two separate SQLite files (invariant: config and state are never mixed):

- `KERDOOS_CONFIG_DB` (default `config.db`) -- `ConfigStore`: sites, products,
  sources, owners, digest jobs.
- `KERDOOS_STATE_DB` (default `state.db`) -- `StateStore`: scrape history,
  job runs.

Both default to the current working directory; set the two env vars to a
persistent volume path in any long-lived deployment.

## Run the tests

```bash
uv run pytest
```

Runs the suite under `tests/` (`testpaths = ["tests"]`, root `pyproject.toml`).

## Build the Docker image

Two build targets (`Dockerfile`), selecting how much of the anti-bot fetch
stack ships in the image:

```bash
docker build --target slim       -t kerdoos:slim .        # http + tls tiers only
docker build --target autonomous -t kerdoos:autonomous .  # + browser + uc tiers (ships Chromium)
```

Or via `docker-compose.yml` profiles:

```bash
docker compose --profile slim up        # http + tls tiers only
docker compose --profile autonomous up  # + browser + uc tiers
```

Both images expose port 8000 and run the WebUI
(`uvicorn kerdoos.interfaces.web.app:create_app --factory`).
