"""The router's unknown-tier error is part of autolycos.errors."""

from __future__ import annotations

import unittest

from autolycos import errors, router


class UnknownFetcherErrorTest(unittest.TestCase):
    def test_router_raises_the_errors_module_class(self) -> None:
        self.assertIs(router.UnknownFetcherError, errors.UnknownFetcherError)
        self.assertTrue(issubclass(errors.UnknownFetcherError, KeyError))


if __name__ == "__main__":
    unittest.main()
