"""HIGH-1: the token path traverser is structural-only (no reflection)."""

from __future__ import annotations

import unittest

from kerdoos.parsers.pathtraverse import PathResolutionError, resolve_path


class PathTraverseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.data = {
            "a": {"b": {"c": 42}},
            "list": [{"x": 1}, {"x": 2}],
            "nested": [[10, 20], [30, 40]],
        }

    def test_resolves_nested_dict(self) -> None:
        self.assertEqual(resolve_path(self.data, "a.b.c"), 42)

    def test_resolves_list_index(self) -> None:
        self.assertEqual(resolve_path(self.data, "list[1].x"), 2)

    def test_resolves_double_index(self) -> None:
        self.assertEqual(resolve_path(self.data, "nested[1][0]"), 30)

    def test_missing_key_raises(self) -> None:
        with self.assertRaises(PathResolutionError):
            resolve_path(self.data, "a.zzz")

    def test_index_out_of_range_raises(self) -> None:
        with self.assertRaises(PathResolutionError):
            resolve_path(self.data, "list[9].x")

    def test_non_integer_index_raises(self) -> None:
        with self.assertRaises(PathResolutionError):
            resolve_path(self.data, "list[x]")

    def test_index_on_non_list_raises(self) -> None:
        with self.assertRaises(PathResolutionError):
            resolve_path(self.data, "a[0]")

    def test_key_on_non_dict_raises(self) -> None:
        with self.assertRaises(PathResolutionError):
            resolve_path(self.data, "a.b.c.d")

    def test_dunder_is_treated_as_plain_key_not_attribute(self) -> None:
        # '__class__' must be a dict lookup that MISSES, never getattr().
        with self.assertRaises(PathResolutionError):
            resolve_path(self.data, "__class__")
        with self.assertRaises(PathResolutionError):
            resolve_path(self.data, "a.__dict__")

    def test_no_attribute_access_on_objects(self) -> None:
        # An arbitrary object exposes attributes; the traverser must not reach
        # them -- it only subscripts dicts/lists.
        class Obj:
            secret = "leak"

        with self.assertRaises(PathResolutionError):
            resolve_path({"o": Obj()}, "o.secret")


if __name__ == "__main__":
    unittest.main()
