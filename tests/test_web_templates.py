"""tier_level / tier() macro: the fetcher escalation micro-indicator.

_TIER_LADDER must use the SAME tier names as the real Fetcher adapters
(method_name), never a stale/renamed alias -- otherwise tier_level() silently
falls through to 0 (unknown) for a tier that is actually the top of the
escalation ladder (invariant #6: http -> tls -> browser -> uc).
"""

from __future__ import annotations

import unittest

from autolycos.router import known_tiers
from kerdoos.interfaces.web.templates import (
    _TIER_COST_ORDER, templates, tier_level)


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

    def test_cost_order_ranks_every_router_tier(self) -> None:
        # The ladder membership is derived, so only the rank table can drift:
        # a tier the router knows but this table omits would render unranked
        # at the end of the list instead of at its escalation depth, and a
        # stale name (a renamed tier) would rank something that never renders.
        self.assertEqual(set(_TIER_COST_ORDER), known_tiers())

    def test_level_normalises_case_and_padding(self) -> None:
        for name in known_tiers():
            with self.subTest(tier=name):
                self.assertEqual(
                    tier_level(f"  {name.upper()}  "), tier_level(name))


class TierMacroRenderTest(unittest.TestCase):
    def _render(self, method: str) -> str:
        tmpl = templates.env.from_string(
            '{% from "_macros.html" import tier %}{{ tier(method) }}')
        return tmpl.render(method=method)

    def _render_with_ladder(self, method: str, ladder: tuple[str, ...]) -> str:
        # An imported macro binds the environment globals once, when Jinja
        # builds the template module, and that module is cached with the
        # template: without dropping the cache on both sides, the override
        # would be a no-op or would leak into the next test, depending on
        # which one imported _macros.html first.
        original = templates.env.globals["tier_ladder"]
        templates.env.globals["tier_ladder"] = ladder
        templates.env.cache.clear()
        try:
            return self._render(method)
        finally:
            templates.env.globals["tier_ladder"] = original
            templates.env.cache.clear()

    def test_uc_source_renders_four_lit_pips(self) -> None:
        html = self._render("uc")
        self.assertEqual(html.count("tier__pip--on"), 4)

    def test_browser_source_renders_three_lit_pips(self) -> None:
        html = self._render("browser")
        self.assertEqual(html.count("tier__pip--on"), 3)

    def test_pip_count_matches_the_router_tier_count(self) -> None:
        html = self._render("http")
        self.assertEqual(html.count('class="tier__pip'), len(known_tiers()))

    def test_pip_count_follows_a_longer_ladder(self) -> None:
        # The relation above is satisfied by a frozen literal as long as the
        # router happens to hold that many tiers; only stretching the ladder
        # tells a derived count from a hardcoded one.
        stretched = tuple(sorted(known_tiers())) + ("spare-rung",)
        html = self._render_with_ladder("http", stretched)
        self.assertEqual(html.count('class="tier__pip'), len(stretched))


if __name__ == "__main__":
    unittest.main()
