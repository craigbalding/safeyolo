#!/usr/bin/env python3
"""Generate the Python 3.12 Unicode categories used by the native scanner."""

from __future__ import annotations

import hashlib
import json
import sys
import unicodedata
from pathlib import Path


EXPECTED_PYTHON = "3.12"
EXPECTED_UNICODE = "15.0.0"
EXPECTED_SHA256 = "2c3271da5c3d9aac327ec5fc8bf3f775348d1342626969cfafb61f32a1b169c1"


def ranges(predicate):
    result = []
    start = None
    for point in range(0x110000):
        present = predicate(chr(point))
        if present and start is None:
            start = point
        elif not present and start is not None:
            result.append([start, point - 1])
            start = None
    if start is not None:
        result.append([start, 0x10FFFF])
    return result


def main() -> int:
    if sys.version_info[:2] != (3, 12) or unicodedata.unidata_version != EXPECTED_UNICODE:
        raise SystemExit(
            f"requires Python {EXPECTED_PYTHON} / Unicode {EXPECTED_UNICODE}; "
            f"got {sys.version_info.major}.{sys.version_info.minor} / {unicodedata.unidata_version}"
        )
    data = {
        "word": ranges(lambda char: char == "_" or unicodedata.category(char)[0] in "LN"),
        "decimal": ranges(lambda char: unicodedata.category(char) == "Nd"),
    }
    encoded = (json.dumps(data, separators=(",", ":")) + "\n").encode()
    actual = hashlib.sha256(encoded).hexdigest()
    if actual != EXPECTED_SHA256:
        raise SystemExit(f"generated data hash changed: {actual}")
    destination = Path(__file__).parents[1] / "data/inspection/unicode.json"
    destination.write_bytes(encoded)
    print(f"wrote {destination} ({len(encoded)} bytes, sha256 {actual})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
