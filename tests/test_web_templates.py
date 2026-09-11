"""tier_level / tier() macro: the fetcher escalation micro-indicator.

_TIER_LADDER must use the SAME tier names as the real Fetcher adapters
(method_name), never a stale/renamed alias -- otherwise tier_level() silently
falls through to 0 (unknown) for a tier that is actually the top of the
escalation ladder (invariant #6: http -> tls -> browser -> uc).
"""

from __future__ import annotations

import unittest

from kerdoos.interfaces.web.templates import templates, tier_level


class TierLevelTest(unittest.TestCase):
    def test_uc_is_above_browser(self) -> None:
        self.assertGreater(tier_level("uc"), tier_level("browser"))

    def test_uc_is_top_of_the_ladder(self) -> None:
        self.assertEqual(tier_level("uc"), 4)

    def test_ladder_order_matches_the_escalation_invariant(self) -> None:
        self.assertEqual(tier_level("http"), 1)
        self.assertEqual(tier_level("tls"), 2)
        self.assertEqual(tier_level("browser"), 3)
        self.assertEqual(tier_level("uc"), 4)

    def test_unknown_method_is_zero(self) -> None:
        self.assertEqual(tier_level("uc_selenium"), 0)
        self.assertEqual(tier_level(None), 0)


class TierMacroRenderTest(unittest.TestCase):
    def _render(self, method: str) -> str:
        tmpl = templates.env.from_string(
            '{% from "_macros.html" import tier %}{{ tier(method) }}')
        return tmpl.render(method=method)

    def test_uc_source_renders_four_lit_pips(self) -> None:
        html = self._render("uc")
        self.assertEqual(html.count("tier__pip--on"), 4)

    def test_browser_source_renders_three_lit_pips(self) -> None:
        html = self._render("browser")
        self.assertEqual(html.count("tier__pip--on"), 3)


if __name__ == "__main__":
    unittest.main()
