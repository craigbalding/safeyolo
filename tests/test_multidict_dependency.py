"""Finite checks for GHSA-54p9-h82j-f925 and the retained yarl consumer."""

import gc
import operator
import sys
import unittest

from multidict import CIMultiDict, MultiDict, MultiDictProxy
from yarl import URL

from safeyolo.detection.matching import matches_resource_pattern, normalize_path


class MultidictDependencyTests(unittest.TestCase):
    @unittest.skipUnless(sys.implementation.name == "cpython", "Requires CPython reference counts")
    def test_items_view_operations_release_operand_values(self):
        # The advisory identifies reflected union and subtraction over tuples.
        # Forward union and intersection exercise the unaffected control paths.
        cases = (
            ("reflected union", operator.or_, True),
            ("subtraction", operator.sub, False),
            ("forward union control", operator.or_, False),
            ("intersection control", operator.and_, False),
        )
        for dictionary_type in (MultiDict, CIMultiDict):
            for name, operation, operand_first in cases:
                with self.subTest(dictionary=dictionary_type.__name__, operation=name):
                    view = dictionary_type(seed="stored").items()
                    sentinel = object()
                    operand = [(f"query-{index}", sentinel) for index in range(32)]
                    left, right = (operand, view) if operand_first else (view, operand)
                    expected = operation(set(left), set(right))
                    gc.collect()
                    reference_count = sys.getrefcount(sentinel)
                    result = operation(left, right)
                    self.assertEqual(result, expected)
                    del result
                    gc.collect()
                    self.assertEqual(sys.getrefcount(sentinel), reference_count)

    def test_yarl_preserves_repeated_and_encoded_query_values(self):
        url = URL("https://example.test/v1/a%20b?q=one&q=two&separator=%2F%3F")
        self.assertEqual(url.path, "/v1/a b")
        self.assertIsInstance(url.query, MultiDictProxy)
        self.assertEqual(url.query.getall("q"), ["one", "two"])
        self.assertEqual(url.query["separator"], "/?")
        changed = url.with_query([("q", "three"), ("q", "four")])
        self.assertEqual(changed.query.getall("q"), ["three", "four"])
        self.assertEqual(url.query.getall("q"), ["one", "two"])

    def test_detection_uses_yarl_path_normalization(self):
        self.assertEqual(normalize_path("//v1///chat/"), "/v1/chat")
        self.assertEqual(normalize_path("/v1/a%20b/"), "/v1/a b")
        self.assertTrue(matches_resource_pattern("API.EXAMPLE.TEST/v1/a%20b/", "api.example.test/v1/*"))
        self.assertFalse(matches_resource_pattern("API.EXAMPLE.TEST/v1/a%20b/", "api.example.test/v2/*"))


if __name__ == "__main__":
    unittest.main()
