"""Run controlled offline cases against service_checker.py inside a guest."""

import argparse
import base64
import json
import runpy
import sys
import unittest
from pathlib import Path

URL = "https://api.github.com/repos/owner/repository/issues/1"


class ServiceCheckerTests(unittest.TestCase):
    def request(self):
        return {"subject": {"kind": "value", "value": "1"}, "inputs": {
            "repository": "owner/repository", "expected_author_id": "42"}}

    def capture(self):
        return {"url": URL, "number": 1, "id": 123, "title": "Example issue",
                "updated_at": "2026-01-01T00:00:00Z", "user": {"id": 42},
                "body": "controlled example " * 2000}

    def evaluate(self, data):
        offset = 0

        def call(value):
            nonlocal offset
            if value["kind"] == "service":
                self.assertEqual(value, {"kind": "service", "service": "github", "method": "GET", "url": URL})
                return {"id": "controlled-capture", "status": 200, "bytes": len(data)}
            self.assertEqual(value, {"kind": "read", "id": "controlled-capture", "offset": offset, "length": 16384})
            chunk = data[offset:offset + value["length"]]
            offset += len(chunk)
            return {"total_bytes": len(data), "data_base64": base64.b64encode(chunk).decode()}

        return self.service_check(self.request(), call)

    def test_matching_author(self):
        self.assertEqual(self.evaluate(json.dumps(self.capture()).encode()),
                         {"finding": {"kind": "finding", "positive": True}})

    def test_other_author(self):
        capture = self.capture()
        capture["user"]["id"] = 43
        self.assertFalse(self.evaluate(json.dumps(capture).encode())["finding"]["positive"])

    def test_pull_request(self):
        capture = self.capture()
        capture["pull_request"] = {}
        self.assertFalse(self.evaluate(json.dumps(capture).encode())["finding"]["positive"])

    def test_wrong_repository(self):
        capture = self.capture()
        capture["url"] = URL.replace("owner/repository", "other/repository")
        with self.assertRaises(ValueError):
            self.evaluate(json.dumps(capture).encode())

    def test_malformed_evidence(self):
        with self.assertRaises(ValueError):
            self.evaluate(b'{"user":')

    def test_missing_author(self):
        capture = self.capture()
        del capture["user"]
        with self.assertRaises(KeyError):
            self.evaluate(json.dumps(capture).encode())

    def test_denied_service(self):
        def denied(_value):
            raise PermissionError("controlled service denial")

        with self.assertRaisesRegex(PermissionError, "controlled service denial"):
            self.service_check(self.request(), denied)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checker", type=Path)
    arguments = parser.parse_args()
    ServiceCheckerTests.service_check = staticmethod(runpy.run_path(str(arguments.checker))["service_check"])
    unittest.main(argv=[sys.argv[0]])
