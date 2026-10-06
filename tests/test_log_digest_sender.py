"""LogDigestSender, the fallback when SMTP is not configured, labels each
logged digest line with the owner's "{product} -- {site}"."""

from __future__ import annotations

import unittest

from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.digest.render import UNKNOWN_SOURCE_LABEL
from kerdoos.digest.sender import LogDigestSender
from kerdoos.parsers.ports import ParserSpec
from kerdoos.persistence.ports import ScrapeRecord
from kerdoos.registry.ports import (
    DigestJob, Product, ProductSource, Registry, SiteConfig,
)

_SID = "aw3225qf:kabum:7c5fc8d1bcd7"


class _OneSourceConfigStore:
    def load(self, owner: str) -> Registry:
        source = ProductSource(
            source_id=_SID, product_id="aw3225qf", site="kabum",
            url="https://www.kabum.com.br/produto/1/a")
        return Registry(
            sites={"kabum": SiteConfig(
                name="kabum", fetcher="http", domain="kabum.com.br",
                parser=ParserSpec(kind="statejson", pix="a", card="b",
                                  availability="c"))},
            products=(Product(id="aw3225qf", name="RTX", sources=(source,)),),
        )

    def site_domains(self) -> frozenset[str]:
        return frozenset({"kabum.com.br"})


class LogDigestSenderLabelTest(unittest.TestCase):
    def test_logged_digest_labels_the_source_with_product_and_site(self) -> None:
        job = DigestJob(
            id="job1", owner_id="owner1", name="daily",
            frequency_kind="daily", schedule_cron="0 0 * * *")
        record = ScrapeRecord(
            source_id=_SID, ts="2026-07-13T00:00:00+00:00",
            status=ScrapeStatus.OK, price_pix_cents=755800,
            price_card_cents=755800, currency="BRL",
            availability=Availability.IN_STOCK, method="http", error=None)

        with self.assertLogs("kerdoos.digest.sender", level="INFO") as logs:
            sent = LogDigestSender(_OneSourceConfigStore()).send(
                job, [record], "2026-07-13T00:00:00+00:00", {})

        self.assertTrue(sent)
        output = "\n".join(logs.output)
        self.assertIn("RTX -- kabum", output)
        self.assertNotIn(UNKNOWN_SOURCE_LABEL, output)


if __name__ == "__main__":
    unittest.main()
