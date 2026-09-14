# AGENTS.md

Guidance for AI coding agents working in this repository. Think of it as a README
for agents: read it before making changes. For the product overview see
`README.md`; for the architecture rationale see `docs/adr/`; for the WebUI
design guide see `DESIGN.md`.

## What this project is

Kerdoos monitors price and availability of tech products on bot-protected
Brazilian e-commerce sites and emails configurable digests. It is a hexagonal
(ports and adapters) application: the core depends only on stable ports, never on
concrete tools. The anti-bot subsystem lives in `packages/autolycos` (being
extracted to its own repo and PyPI package).

## Repository layout

```
packages/kerdoos/src/kerdoos/
  core/           orchestrator, scheduler, retry, state machine, app use-cases
  registry/       ConfigStore (sites, products, sources, jobs), schemas
  parsers/        Parser port + adapters (jsonld, css, nextdata, regex)
  digest/         aggregation and mail rendering
  persistence/    StateStore (SQLite), repositories
  interfaces/     cli/ and web/ (thin views over core)
packages/autolycos/  anti-bot subsystem (Fetcher tiers; never imports kerdoos)
config/              sites.yaml, products.yaml
docs/adr/            architecture decision records (authoritative)
```

## Build, test, tooling

- Dependency and workspace management: `uv`. Run `uv sync` to set up.
- Tests: `uv run pytest` (pytest, httpx). The suite must stay green.
- Lint and format: `ruff` (`ruff check`, `ruff format`).
- Target Python: `>=3.11`.
- Do not introduce a new tool chain without an ADR. The stack above is decided
  (see `docs/adr/0002`).
- Some tests skip outside the `autonomous` Docker image (no real Chromium on
  a plain dev machine). Mandatory before pushing a change to `uc.py`,
  `autolycos/safety.py`, the `Dockerfile`, or a `uv.lock` update touching
  `seleniumbase`/`patchright`:
  ```bash
  docker build --target autonomous -t kerdoos:autonomous .
  docker run --rm -e KERDOOS_REQUIRE_IMAGE_TESTS=1 \
    -v "$(pwd)/tests:/tmp/tests:ro" kerdoos:autonomous \
    sh -c "cd /tmp && python3 -m pytest tests/image/test_uc_image.py -k UcPinExecution"
  ```
  `KERDOOS_REQUIRE_IMAGE_TESTS=1` turns the skip into a hard failure if the
  image lacks a real Chromium -- a silent skip must never read as a pass.
- Camoufox tier image proofs (`tests/image/test_camoufox_image.py`) need TWO
  separate invocations, since a test cannot drop its own container's
  network from inside itself:
  ```bash
  # Normal invocation: everything except the --network none proof.
  docker build --target autonomous -t kerdoos:autonomous .
  docker run --rm -e KERDOOS_REQUIRE_IMAGE_TESTS=1 \
    -v "$(pwd)/tests:/tmp/tests:ro" kerdoos:autonomous \
    sh -c "cd /tmp && python3 -m pytest tests/image/test_camoufox_image.py"

  # --network none invocation: the zero-download-under-no-network proof
  # only runs (hard-fails otherwise) when KERDOOS_IMAGE_NETWORK_NONE=1 is
  # also set -- the marker is the caller's explicit promise that this
  # process really was started under --network none; without it the test
  # skips rather than infer network state from a reachability probe alone.
  docker run --rm --network none \
    -e KERDOOS_REQUIRE_IMAGE_TESTS=1 -e KERDOOS_IMAGE_NETWORK_NONE=1 \
    -v "$(pwd)/tests:/tmp/tests:ro" kerdoos:autonomous \
    sh -c "cd /tmp && python3 -m pytest tests/image/test_camoufox_image.py::CamoufoxNoNetworkZeroDownloadTest"
  ```
  The strace-based proofs in the same file (network syscall audit) need a
  separate TEST-only image (`autonomous-test` target, `strace` installed)
  and `--cap-add SYS_PTRACE` at `docker run` -- never added to the shipped
  image:
  ```bash
  docker build --target autonomous-test -t kerdoos:autonomous-test .
  docker run --rm --cap-add SYS_PTRACE \
    -e KERDOOS_REQUIRE_IMAGE_TESTS=1 -e KERDOOS_IMAGE_STRACE=1 \
    -v "$(pwd)/tests:/tmp/tests:ro" kerdoos:autonomous-test \
    sh -c "cd /tmp && python3 -m pytest tests/image/test_camoufox_image.py -k StraceNetworkAudit"
  ```
  A few proofs need real outbound network to github.com (binary provenance
  check), separate from the browser's own SSRF-pinned proxy:
  ```bash
  docker run --rm -e KERDOOS_REQUIRE_IMAGE_TESTS=1 -e KERDOOS_IMAGE_ONLINE=1 \
    -v "$(pwd)/tests:/tmp/tests:ro" kerdoos:autonomous \
    sh -c "cd /tmp && python3 -m pytest tests/image/test_camoufox_image.py -k BinaryProvenance"
  ```
  Each `KERDOOS_IMAGE_*` marker is the caller's promise that the matching
  precondition holds; set with `KERDOOS_REQUIRE_IMAGE_TESTS=1` and the
  precondition still missing, the proof hard-fails instead of skipping.

## Invariants (do not violate)

1. **No tool leaks into `core/`.** The core imports ports, never `playwright`,
   `curl_cffi`, `patchright`, `seleniumbase`, etc. Those live only in
   `packages/autolycos/adapters/` and concrete parsers in `parsers/`.
2. **`autolycos/` never imports `kerdoos`/`core`.** The subsystem stays
   extractable as a standalone package. The dependency is one-way.
3. **Three-value state `{ok, indeterminate, unavailable}`.** Never confuse a
   transient block (anti-bot, isolated 5xx) with a real stock-out
   (`availability: OutOfStock`).
4. Collection reads the current price; it does not check a frozen value.
5. Retry with backoff on non-determinism.
6. Fetcher tiers ordered by increasing cost: `http` < `tls` < `browser` < `uc`
   (deprecated) < `camoufox`. The order is a cost, not a path: there is no
   automatic escalation, each site declares the cheapest tier that passes.
7. **Config and state are separate stores** (`ConfigStore` vs `StateStore`),
   each behind its abstraction, so storage can migrate without touching the core.
8. Digests are per-owner and configurable; never a hardcoded per-product blast.
9. **Interfaces are thin.** CLI and WebUI carry no business logic; it lives in
   the core use-cases.

Multi-tenant rule: `owner_id` comes from the authenticated principal, never from
the request body, and scoping is enforced in SQL as the last line of defense.
`owner_id` is never serialized to the client.

## Conventions

- Code, inline comments, logs, identifiers: **English**.
- Documentation (`.md`), commit messages, design reasoning: **French** (public
  README and package metadata stay English for a broad audience).
- **No em dashes** anywhere (commits, docs, code comments). Use `--` or rewrite.
- No hardcoded secrets, credentials, or hosting infrastructure. Read SMTP and
  paths from configuration or environment. Assume the repository may become
  public.

## Change discipline

- Before writing new code, understand the affected use-case and its callers.
  Read before you edit; search all call sites of a shared symbol before changing
  it.
- Preserve the port and adapter boundary. New capability behind a port is a new
  adapter, not a change to the core.
- Keep tests load-bearing: a test that passes even when the behavior is broken is
  a gap, not coverage.
- Non-trivial changes are reviewed for correctness, security (SSRF, tenant
  isolation, XSS, CSRF, header injection), and architecture before merge.

## Where the truth lives

- `docs/adr/0000` -- founding decisions (monorepo vs submodule, no
  changedetection.io fork, SQLite over flat files).
- `docs/adr/0001` -- post-MVP platform (WebUI, MCP, multi-tenant).
- `docs/adr/0002` -- productionisation (scheduler, packaging, tooling).
- `docs/adr/0003` -- digest jobs and notification rules.
- `DESIGN.md` -- WebUI design guide (tokens, typography, state matrix,
  layout), not an architecture document.
When code and a document disagree, trust the code and flag the drift.
