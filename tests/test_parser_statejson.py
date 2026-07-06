"""statejson parser: real fixture + edge cases (price encoding, availability)."""

from __future__ import annotations

import json
import pathlib
import unittest

from core.domain import Availability, ParseError
from parsers.adapters.statejson import StateJsonParser, _to_cents
from parsers.ports import ParserSpec

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "kabum_aw3225qf.html"

KABUM_SPEC = ParserSpec(
    kind="statejson",
    pix="props.pageProps.product.prices.priceWithDiscount",
    card="props.pageProps.product.prices.price",
    availability="props.pageProps.product.available",
)


def _html(state: dict) -> str:
    payload = json.dumps(state)
    return (f'<html><body><script id="__NEXT_DATA__" '
            f'type="application/json">{payload}</script></body></html>')


def _state(pix=None, card=None, available=None) -> dict:
    return {"props": {"pageProps": {"product": {
        "prices": {"priceWithDiscount": pix, "price": card},
        "available": available,
    }}}}


class StateJsonFixtureTest(unittest.TestCase):
    def test_real_kabum_fixture(self) -> None:
        html = FIXTURE.read_text(encoding="utf-8")
        extract = StateJsonParser(KABUM_SPEC).extract(html)
        # Ground truth on the captured page: R$ 7.558,00.
        self.assertEqual(extract.price_pix_cents, 755800)
        self.assertEqual(extract.price_card_cents, 755800)
        self.assertEqual(extract.currency, "BRL")
        self.assertEqual(extract.availability, Availability.IN_STOCK)


class StateJsonEncodingTest(unittest.TestCase):
    def test_reais_float_to_cents_rounds(self) -> None:
        extract = StateJsonParser(KABUM_SPEC).extract(
            _html(_state(pix=73.58, card=11.9, available=True)))
        self.assertEqual(extract.price_pix_cents, 7358)
        self.assertEqual(extract.price_card_cents, 1190)

    def test_integer_reais_to_cents(self) -> None:
        extract = StateJsonParser(KABUM_SPEC).extract(
            _html(_state(pix=7558, card=7558, available=True)))
        self.assertEqual(extract.price_pix_cents, 755800)

    def test_zero_or_negative_price_is_absent(self) -> None:
        # Only card present; pix=0 -> treated as absent (NULL != 0).
        extract = StateJsonParser(KABUM_SPEC).extract(
            _html(_state(pix=0, card=99.9, available=True)))
        self.assertIsNone(extract.price_pix_cents)
        self.assertEqual(extract.price_card_cents, 9990)


class ToCentsUnitTest(unittest.TestCase):
    def test_enormous_finite_value_is_none(self) -> None:
        # 1e308 is finite but value*100 overflows to inf; round(inf) raises
        # OverflowError, caught locally -> None (invalid price sanity contract).
        self.assertIsNone(_to_cents(1e308))

    def test_infinity_and_nan_are_none(self) -> None:
        self.assertIsNone(_to_cents(float("inf")))
        self.assertIsNone(_to_cents(float("nan")))

    def test_regular_value_rounds_to_cents(self) -> None:
        self.assertEqual(_to_cents(73.58), 7358)


class StateJsonAvailabilityTest(unittest.TestCase):
    def test_available_false_is_out_of_stock(self) -> None:
        extract = StateJsonParser(KABUM_SPEC).extract(
            _html(_state(pix=100.0, available=False)))
        self.assertEqual(extract.availability, Availability.OUT_OF_STOCK)

    def test_missing_availability_path_degrades_to_unknown(self) -> None:
        spec = ParserSpec(
            kind="statejson",
            pix="props.pageProps.product.prices.priceWithDiscount",
            card="props.pageProps.product.prices.price",
            availability="props.pageProps.product.does_not_exist",
        )
        extract = StateJsonParser(spec).extract(
            _html(_state(pix=100.0, available=True)))
        self.assertEqual(extract.availability, Availability.UNKNOWN)

    def test_no_availability_path_is_unknown(self) -> None:
        spec = ParserSpec(
            kind="statejson",
            pix="props.pageProps.product.prices.priceWithDiscount",
            card="props.pageProps.product.prices.price",
            availability=None,
        )
        extract = StateJsonParser(spec).extract(
            _html(_state(pix=100.0, available=True)))
        self.assertEqual(extract.availability, Availability.UNKNOWN)


class StateJsonFailureTest(unittest.TestCase):
    def test_no_next_data_raises_parse_error(self) -> None:
        with self.assertRaises(ParseError):
            StateJsonParser(KABUM_SPEC).extract("<html><body>nope</body></html>")

    def test_invalid_json_raises_parse_error(self) -> None:
        html = ('<html><script id="__NEXT_DATA__">{not valid json}'
                '</script></html>')
        with self.assertRaises(ParseError):
            StateJsonParser(KABUM_SPEC).extract(html)

    def test_no_price_raises_parse_error(self) -> None:
        with self.assertRaises(ParseError):
            StateJsonParser(KABUM_SPEC).extract(
                _html(_state(pix=None, card=None, available=True)))

    def test_infinity_and_nan_prices_are_absent(self) -> None:
        # json.dumps emits the Python-only Infinity/NaN tokens; json.loads
        # accepts them. isfinite() must reject them -> no price -> ParseError.
        html = _html(_state(pix=float("inf"), card=float("nan"),
                            available=True))
        with self.assertRaises(ParseError):
            StateJsonParser(KABUM_SPEC).extract(html)

    def test_infinity_price_falls_back_to_finite_card(self) -> None:
        extract = StateJsonParser(KABUM_SPEC).extract(
            _html(_state(pix=float("inf"), card=99.9, available=True)))
        self.assertIsNone(extract.price_pix_cents)   # inf rejected
        self.assertEqual(extract.price_card_cents, 9990)

    def test_enormous_finite_price_is_absent(self) -> None:
        # 1e308 is finite (isfinite True) but value*100 overflows to inf and
        # round(inf) raises OverflowError -> must degrade to None locally
        # (invalid price), not escalate to INDETERMINATE via the orchestrator.
        extract = StateJsonParser(KABUM_SPEC).extract(
            _html(_state(pix=1e308, card=99.9, available=True)))
        self.assertIsNone(extract.price_pix_cents)   # enormous rejected
        self.assertEqual(extract.price_card_cents, 9990)

    def test_enormous_price_only_raises_parse_error(self) -> None:
        # No usable price at all -> ParseError (fail-closed), never crash.
        with self.assertRaises(ParseError):
            StateJsonParser(KABUM_SPEC).extract(
                _html(_state(pix=1e308, card=None, available=True)))

    def test_deeply_nested_json_raises_parse_error(self) -> None:
        # RecursionError from json.loads must fail closed (ParseError), never
        # crash the parser.
        depth = 100_000
        raw = "[" * depth + "]" * depth
        html = (f'<html><script id="__NEXT_DATA__">{raw}</script></html>')
        with self.assertRaises(ParseError):
            StateJsonParser(KABUM_SPEC).extract(html)


if __name__ == "__main__":
    unittest.main()
