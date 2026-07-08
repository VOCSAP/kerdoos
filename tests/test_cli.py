"""CLI resilience: one failing source never aborts the run nor the digest.

Invariants #3 (three-valued state) + #8 (single aggregated digest). The failing
source is simulated at the scrape level (monkeypatched), so the test is hermetic
(no network): router.select / build_parser run for real but never touch the net.

Phase 1: `run` reads from config.db, not YAML directly (invariant #9 -- the
CLI is a thin AppService wrapper), so this test first goes through
`config import` to seed a fresh config.db, mirroring real CLI usage.
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.interfaces.cli import main as cli
from kerdoos.persistence.ports import ScrapeRecord

_SITES = """\
sites:
  kabum:
    fetcher: http
    domain: kabum.com.br
    parser:
      kind: statejson
      pix: props.pageProps.product.prices.priceWithDiscount
      card: props.pageProps.product.prices.price
      availability: props.pageProps.product.available
"""

_PRODUCTS = """\
products:
  - id: aw3225qf
    sources:
      - site: kabum
        url: https://www.kabum.com.br/produto/1/a
      - site: kabum
        url: https://www.kabum.com.br/produto/2/b
"""


def _fake_scrape(fetcher, parser, store, owner, source_id, url, *, now=None):
    if "/1/" in url:
        raise RuntimeError("simulated adapter blowup")
    return ScrapeRecord(
        source_id=source_id, ts=now, status=ScrapeStatus.OK,
        price_pix_cents=755800, price_card_cents=755800, currency="BRL",
        availability=Availability.IN_STOCK, method="http", error=None,
    )


class CliResilienceTest(unittest.TestCase):
    def test_one_failing_source_does_not_kill_run_or_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            config_dir = d / "config"
            config_dir.mkdir()
            (config_dir / "sites.yaml").write_text(_SITES, encoding="utf-8")
            (config_dir / "products.yaml").write_text(_PRODUCTS, encoding="utf-8")
            config_db = d / "config.db"
            state_db = d / "state.db"

            import_args = cli.build_parser_cli().parse_args([
                "config", "import",
                "--config-dir", str(config_dir),
                "--config-db", str(config_db),
                "--db", str(state_db),
                "--owner", "owner1",
            ])
            self.assertEqual(cli.cmd_config_import(import_args), 0)

            run_args = cli.build_parser_cli().parse_args([
                "run", "--owner", "owner1",
                "--config-db", str(config_db), "--db", str(state_db)])

            buf = io.StringIO()
            with mock.patch(
                "kerdoos.core.app.services.scrape_and_record", _fake_scrape
            ):
                with contextlib.redirect_stdout(buf):
                    rc = cli.cmd_run(run_args)

        self.assertEqual(rc, 0)
        out = buf.getvalue()
        # Single aggregated digest covering BOTH sources despite one failing.
        self.assertEqual(out.count("Kerdoos daily digest"), 1)
        self.assertIn("sources: 2", out)
        self.assertIn("simulated adapter blowup", out)   # failed source degraded
        self.assertIn("ok=1", out)                        # good source survived
        self.assertIn("indeterminate=1", out)


if __name__ == "__main__":
    unittest.main()
