"""Generate the pinned network guard tables from the existing Python environment.

Run from the repository root with Python 3.12 and confusable-homoglyphs 3.3.1.
The generator reads installed package data; it makes no network requests.
"""

import hashlib
import json
import sys
import unicodedata
from pathlib import Path

import confusable_homoglyphs
from confusable_homoglyphs import categories, confusables


def ranges(points):
    result = []
    for point in points:
        if result and result[-1][1] + 1 == point:
            result[-1][1] = point
        else:
            result.append([point, point])
    return result


def main():
    if sys.version_info[:2] != (3, 12) or unicodedata.unidata_version != "15.0.0":
        raise RuntimeError("generation requires Python 3.12 / Unicode 15.0.0")
    if confusable_homoglyphs.__version__ != "3.3.1":
        raise RuntimeError("generation requires confusable-homoglyphs 3.3.1")
    package = Path(confusable_homoglyphs.__file__).parent
    expected = {
        "categories.json": "804570f15edd97f7cd15f4458cea45bd7df2c1a0d179a7975ed7edb32b1cc9c9",
        "confusables.json": "2d8b4774cd9dc6f233a18681bc00423ae270037437f276fc6a8b80630941fe7d",
    }
    for name, digest in expected.items():
        if hashlib.sha256((package / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"unexpected source data hash: {name}")
    scripts = []
    for low, high, alias, _category in categories.categories_data["code_points_ranges"]:
        if scripts and scripts[-1][1] + 1 == low and scripts[-1][2] == alias:
            scripts[-1][1] = high
        else:
            scripts.append([low, high, alias])
    aliases = categories.categories_data["iso_15924_aliases"]
    safe_categories = {
        "Lu",
        "Ll",
        "Lt",
        "Lm",
        "Lo",
        "Nd",
        "Nl",
        "No",
        "Pc",
        "Pd",
        "Ps",
        "Pe",
        "Pi",
        "Pf",
        "Po",
        "Sm",
        "Sc",
        "Sk",
        "So",
        "Zs",
    }
    data = {
        "common": aliases.index("COMMON"),
        "unknown": len(aliases),
        "scripts": scripts,
        "confusables": ranges(
            sorted(ord(key) for key, value in confusables.confusables_data.items() if len(key) == 1 and value)
        ),
        "safe": ranges(point for point in range(0x110000) if unicodedata.category(chr(point)) in safe_categories),
    }
    destination = Path(__file__).resolve().parents[1] / "data" / "network_guard" / "unicode.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    content = (json.dumps(data, separators=(",", ":")) + "\n").encode()
    destination.write_bytes(content)
    print(f"{destination.name}: sha256 {hashlib.sha256(content).hexdigest()}")
    print(f"ranges: scripts={len(scripts)}, confusables={len(data['confusables'])}, safe={len(data['safe'])}")


if __name__ == "__main__":
    main()
