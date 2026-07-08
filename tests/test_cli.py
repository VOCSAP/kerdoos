"""CLI resilience: one failing source never aborts the run nor the digest.

Invariants #3 (three-valued state) + #8 (single aggregated digest). The failing
source is simulated at the scrape level (monkeypatched), so the test is hermetic
(no network): router.select / build_parser run for real but never touch the net.
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


def _fake_scrape(fetcher, parser, store, source_id, url, *, now=None):
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
            (d / "sites.yaml").write_text(_SITES, encoding="utf-8")
            (d / "products.yaml").write_text(_PRODUCTS, encoding="utf-8")
            args = cli.build_parser_cli().parse_args(
                ["run", "--config-dir", str(d), "--db", ":memory:"])

            buf = io.StringIO()
            with mock.patch.object(cli, "scrape_and_record", _fake_scrape):
                with contextlib.redirect_stdout(buf):
                    rc = cli.cmd_run(args)

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
