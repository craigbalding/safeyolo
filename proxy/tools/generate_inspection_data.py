#!/usr/bin/env python3
"""Generate the pinned Python 3.12 Unicode data used by the native scanner."""

from __future__ import annotations

import hashlib
import json
import sys
import unicodedata
from pathlib import Path

EXPECTED_PYTHON = "3.12"
EXPECTED_UNICODE = "15.0.0"
EXPECTED_SHA256 = "2c3271da5c3d9aac327ec5fc8bf3f775348d1342626969cfafb61f32a1b169c1"
EXPECTED_CANONICAL_NAMES = 143_041
EXPECTED_NAME_ALIASES = 473


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


def name_entries(alias_source: Path):
    canonical = {
        unicodedata.name(chr(point)): point
        for point in range(0x110000)
        if unicodedata.name(chr(point), None) is not None
    }
    if len(canonical) != EXPECTED_CANONICAL_NAMES:
        raise SystemExit(
            f"canonical Unicode name count changed: {len(canonical)}; "
            f"expected {EXPECTED_CANONICAL_NAMES}"
        )

    aliases = {}
    for line in alias_source.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = [field.strip() for field in line.split(";")]
        if len(fields) < 3:
            raise SystemExit(f"malformed Unicode name alias row: {line!r}")
        point, name, alias_type = fields[:3]
        if alias_type not in {"correction", "control", "alternate", "figment", "abbreviation"}:
            raise SystemExit(f"unknown Unicode alias type: {alias_type!r}")
        if not name.isascii() or name != name.upper():
            raise SystemExit(f"non-canonical alias spelling: {name!r}")
        value = int(point, 16)
        if len(chr(value)) != 1 or unicodedata.lookup(name) != chr(value):
            raise SystemExit(f"Python lookup does not verify alias {name!r}")
        if name in canonical or name in aliases:
            raise SystemExit(f"duplicate Unicode name alias: {name!r}")
        aliases[name] = value

    if len(aliases) != EXPECTED_NAME_ALIASES:
        raise SystemExit(
            f"Unicode name alias count changed: {len(aliases)}; "
            f"expected {EXPECTED_NAME_ALIASES}"
        )

    # CPython's name() includes its finite algorithmic Hangul and CJK domains.
    # Keep explicit witnesses here so a runtime/data-version drift cannot make
    # those names disappear silently from the generated table.
    for name in ("HANGUL SYLLABLE GA", "CJK UNIFIED IDEOGRAPH-4E00"):
        value = unicodedata.lookup(name)
        if canonical.get(name) != ord(value):
            raise SystemExit(f"algorithmic Unicode name is not canonical: {name!r}")

    entries = sorted({**canonical, **aliases}.items())
    if len(entries) != EXPECTED_CANONICAL_NAMES + EXPECTED_NAME_ALIASES:
        raise SystemExit(f"unexpected merged Unicode name count: {len(entries)}")
    return entries


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

    aliases = Path(__file__).parents[1] / "data/inspection/NameAliases-15.0.0.txt"
    entries = name_entries(aliases)
    names_destination = Path(__file__).parents[1] / "data/inspection/names.txt"
    names_destination.write_text(
        "# Python 3.12.14 / Unicode 15.0.0 canonical scalar names and aliases\n"
        "# Names are uppercase ASCII; values are Unicode scalar values in hex.\n"
        + "".join(f"{name};{point:x}\n" for name, point in entries),
        encoding="ascii",
    )
    names_hash = hashlib.sha256(names_destination.read_bytes()).hexdigest()
    print(
        f"wrote {names_destination} ({names_destination.stat().st_size} bytes, "
        f"sha256 {names_hash}; {len(entries)} entries)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
