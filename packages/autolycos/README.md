# autolycos

**Fetch web pages that fight back, without your code caring how.**

`autolycos` is an anti-bot fetching subsystem: it resolves access to
bot-protected pages through a ladder of increasingly capable (and costly)
fetcher tiers, behind a single stable port, with fail-closed SSRF guards. It
is domain-agnostic by design -- the caller injects a `DomainPolicy`, so the
library carries no hardcoded allowlist and can be reused across projects.

> **Pre-release.** The public API is not frozen yet and may change before the
> first stable release. Not recommended for production use yet.

## The problem it solves

Fetching a page from a modern e-commerce or content site is rarely a plain
HTTP GET anymore. Sites sit behind bot managers (Cloudflare, Akamai, DataDome,
Kasada) that inspect TLS fingerprints, browser automation signals, and
behavioural signatures. The same URL might return a clean `200` one minute and
a challenge page or `429` the next.

Handling this well means owning several tools of varying cost and capability:
a cheap HTTP call, a TLS impersonation layer, one or more real (undetected)
browsers. Doing this inline, in every project that needs a page, spreads that
complexity everywhere and makes it easy to leak requests to internal addresses
(SSRF) or to confuse a transient block with a real result.

`autolycos` packages that set of tools once, correctly, behind a clean
boundary.

## What it does

It exposes a ladder of fetcher tiers, ordered by increasing cost:

1. `http` -- plain HTTP with a pinned IP (SSRF-safe). Cheapest, works on open
   sites.
2. `tls` -- TLS fingerprint impersonation (`curl_cffi`). Beats TLS-signature
   filters.
3. `browser` -- undetected headless Chromium (`patchright` +
   `playwright-stealth`).
4. `uc` -- undetected Chrome driver (`seleniumbase`), **(deprecated)**, kept
   for a re-evaluation should upstream progress on the one protector it was
   built for.
5. `camoufox` -- undetected headless Firefox (`camoufox`), an alternative
   fingerprint to the Chromium-based tiers above.

A caller asks the `Router` for a named tier and gets back a `Fetcher`; each
call to `fetch(url)` returns a `FetchResult`. The router itself does not
escalate or pick a tier for you: it resolves the name you give it to a
concrete adapter, caching instances. Deciding WHICH tier to try, and whether
to retry a different one on failure, is the caller's own policy -- `autolycos`
gives you the tiers and the safety guarantees each one carries, not an
opinion on when to use which. Your code never imports `patchright`,
`curl_cffi`, `seleniumbase`, or `camoufox` directly, and never has to know
which tool actually rendered the page.

## Why use it

- **A stable port, not a pile of tools.** Your code depends on `Fetcher` /
  `FetchResult` / `Router`. Swapping, adding, or removing a tool is an adapter
  change, not a rewrite of your call sites.
- **Fail-closed SSRF safety by construction.** A single shared predicate
  (`check_scheme_and_domain`) guards the fetch path across every tier so
  the checks can never drift apart between adapters. Rejections raise
  `SSRFError`, never a silent pass. Scheme allowlist closes `javascript:` /
  `file:` / internal targets. The `browser` and `camoufox` tiers additionally
  route all traffic through a loopback egress proxy that pins the resolved
  IP once and refuses any re-resolution; `uc` pins at the DNS layer instead,
  through a Chromium host-resolver rule.
- **Domain-agnostic and reusable.** No hardcoded site list. The caller injects
  a `DomainPolicy`, so the same library serves a price monitor, a content
  archiver, or any tool that needs resilient fetching.
- **Policy separate from tools.** The `Router` (which tier a given fetch
  uses) is a distinct layer from the adapters (the tools themselves), so tier
  selection strategy evolves independently of the fetchers.

## Typical use cases

- Daily price and availability monitoring of products on protected retailers.
- Scraping or archiving pages behind Cloudflare / Akamai / DataDome.
- Any backend that needs "get me this page, reliably, and tell me if you
  could not" without embedding browser-automation plumbing.

## Stable contract (consumer-facing)

- `autolycos.ports`: `Fetcher`, `FetchResult`, `Router`
- `autolycos.safety`: `DomainPolicy`, `check_scheme_and_domain`
- `autolycos.errors`: `SSRFError`, `FetchError`
- `autolycos.router`: `StaticRouter`, `known_tiers`, `UnknownFetcherError`
- `autolycos.browser_gate`: `BrowserGate`

Everything else (`adapters/*`, `challenge`, `egress_proxy`) is internal and
reached only through a `Router` / `DomainPolicy` you construct.

## Install

```bash
pip install autolycos                 # core (http tier)
pip install "autolycos[tls]"          # + TLS impersonation
pip install "autolycos[browser]"      # + undetected Chromium
pip install "autolycos[uc]"           # + undetected Chrome driver
pip install "autolycos[camoufox]"     # + undetected Firefox
```

Extras are additive: install only the tiers you actually need. None of the
three heavier extras ships a working browser binary on `pip install` alone:
`browser` needs `patchright install chromium` run once after install;
`uc` needs a `seleniumbase`-managed `uc_driver` matching the installed
Chromium's major version; `camoufox` never downloads a binary at fetch time
by design (the adapter always passes an explicit path and version), so the
matching Camoufox release must be provisioned separately before first use.

## Name

Autolycos, son of Hermes, was the master of disguise and sleight of hand. The
library wears the same trick: it changes its fingerprint to pass unnoticed.

## License

Apache-2.0. See [LICENSE](https://github.com/VOCSAP/autolycos/blob/main/LICENSE).
