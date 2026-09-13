# kerdoos

**Daily price and availability monitoring for tech products on Brazilian
e-commerce, delivered as email digests you configure yourself.**

Kerdoos watches product pages on protected retailers (MercadoLivre, Magalu,
Terabyte, Pichau, Amazon, Kabum), records their price and stock state every day,
and emails you a digest. You decide what goes in each digest and how often it is
sent.

> Status: platform under active development. The scraping core, multi-tenant
> config, authentication, and WebUI are in place; the notification jobs and
> packaging are being built.

## What it does

- **Tracks price and availability** of the products you register, on sites that
  actively resist scraping.
- **Distinguishes three states**, never guessing: `ok` (read succeeded),
  `indeterminate` (a transient block or anti-bot challenge), and `unavailable`
  (genuinely out of stock). A temporary block is never reported as a stock-out.
- **Sends configurable digests.** You create notification jobs, each with its own
  selection of products and sources, its own schedule (hourly, daily, custom),
  timezone, and template. One aggregated digest, one product, or anything in
  between.
- **Multi-tenant WebUI.** Each account manages its own products, sources, digest
  jobs, and API tokens, behind session authentication.

## How it is built

Kerdoos is a hexagonal (ports and adapters) application. The core knows only
stable **ports**, never concrete tools:

- `Fetcher` -- resolve access to a URL (anti-bot tiers of increasing cost).
- `Parser` -- extract price, currency, and availability from a page.
- `ConfigStore` -- source of configuration (sites, products, jobs).
- `StateStore` -- persistence of scrape history.

Adding, removing, or swapping a tool means writing an adapter, never touching the
core. Configuration and state are kept in separate stores so migrating storage
(SQLite today, Postgres later) does not touch business logic.

## Autolycos, the anti-bot subsystem

The hard part of this product is getting the page at all. That lives in
[**autolycos**](https://github.com/VOCSAP/autolycos), a standalone subsystem that
offers fetcher tiers of increasing cost (`http`, `tls`, `browser`, `uc`
deprecated, `camoufox`), each site declaring the cheapest one that passes, behind a
stable port, with fail-closed SSRF guards. It is domain-agnostic and reusable on
its own. Kerdoos is the orchestrator (scheduling, retries, state machine, digest
aggregation); autolycos is how it reaches protected sites.

The two names come from the Hermes myth: Kerdoos (an epithet of Hermes, "bringer
of gain") is the core; Autolycos, son of Hermes and master of disguise, is the
fingerprint-spoofing subsystem.

## Layout

```
kerdoos/
  packages/kerdoos/    core, registry, parsers, digest, persistence, interfaces
  packages/autolycos/  anti-bot subsystem (workspace member, being extracted)
  config/              sites and products
  docs/adr/            architecture decision records (source of truth)
  DESIGN.md            WebUI design guide (tokens, states, layout)
```

## Development

Uses a `uv` workspace. Common commands:

```bash
uv sync                 # install workspace and dependencies
uv run pytest           # run the test suite
```

Tooling is `uv` (dependencies) plus `ruff` (lint and format) plus `pytest`
(tests). See `AGENTS.md` for conventions and invariants, `docs/adr/` for the
architecture rationale, and `DESIGN.md` for the WebUI design guide.

## Deployment

Kerdoos targets a single-container deployment: it runs its own browser, schedules
its own digests, and needs only an SMTP relay (read from configuration, never
hardcoded) and a volume for its SQLite databases. The specific host is a
deployment detail, not a design constraint.

Behind a reverse proxy, set `KERDOOS_FORWARDED_ALLOW_IPS` in the Docker image
to the address the proxy connects from (see `env.example`). Left unset, the
Docker image trusts no forwarding header: every request appears to come from
the proxy, so the access log sees a single address. Keep the list as narrow as
the proxy itself: any trusted address can forge the client IP, so an entry
naming far more than a proxy (`*`, or any network wider than a `/8`) is refused
at startup with exit 64. With `restart: unless-stopped` that shows up only as
`Restarting (64)`, and the offending entry is named in the container logs.
Configure the
proxy to overwrite `X-Forwarded-Proto` and append to `X-Forwarded-For` -- in
nginx, `proxy_set_header X-Forwarded-Proto $scheme;` and `proxy_set_header
X-Forwarded-For $proxy_add_x_forwarded_for;` -- otherwise a client can
downgrade the scheme of the slash redirect, the one absolute URL the app
generates.

### MCP server

Kerdoos can also serve an MCP (Model Context Protocol) endpoint from the same
process. It is off by default (`KERDOOS_MCP_ENABLED=false`, see `env.example`).
Enabling it also requires `KERDOOS_PUBLIC_URL`, the URL clients use: without
it the process refuses to start, on purpose. The endpoint is
`<KERDOOS_PUBLIC_URL>/mcp` (`/mcp/` is answered too), and clients authenticate
with a bearer token created on the WebUI profile page. Keep
`KERDOOS_WORKERS=1`: MCP sessions live in a single worker process, so with
more workers a warning is logged at startup and a client can lose its session.
Requests carrying an `Origin` header are refused with 403, whatever its value:
browser-based clients are not supported.

`KERDOOS_FORWARDED_ALLOW_IPS` and `KERDOOS_PUBLIC_URL` answer two different
questions: the first says which proxy is trusted, the second which URL the
client sees. The MCP endpoint only accepts the `Host` headers derived from
`KERDOOS_PUBLIC_URL` (plus any listed in `KERDOOS_MCP_ALLOWED_HOSTS`) and
answers 421 to any other, so the proxy must pass the client's `Host` through.
nginx sends the upstream address by default: set `proxy_set_header Host
$host;`. When `KERDOOS_PUBLIC_URL` has a path prefix that the proxy strips
(for instance `https://example.org/kerdoos`), the MCP discovery metadata is
advertised at `/.well-known/oauth-protected-resource/kerdoos/mcp` on the same
host: route that path to Kerdoos unchanged.

## License

See [LICENSE](./LICENSE).

### Third-party browser engines

The `autonomous` image bundles browser engines that carry their own licenses,
notably [Camoufox](https://github.com/daijro/camoufox) (MPL-2.0), a Firefox fork
used to reach sites behind advanced bot protection. MPL-2.0 is a per-file
copyleft: it applies to Camoufox's own files and leaves this repository's license
untouched. Kerdoos uses Camoufox unmodified.

Publishing this repository (source plus the Dockerfile that fetches the engine at
build time) does not redistribute Camoufox, and carries no further obligation.
Publishing a **built image** does redistribute it: ship the MPL-2.0 license text
and copyright notices, and point recipients to the upstream sources at the pinned
release tag. This is an engineering reading, not legal advice.
