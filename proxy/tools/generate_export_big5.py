#!/usr/bin/env python3
"""Validate and extract the CPython Big5 corrections for the Rust exporter.

The checked-in JSON contains only the 260 mappings where CPython 3.12.14's
``big5`` codec differs from ``encoding_rs`` 0.8.41.  The complete comparison
is kept as review evidence because it contains all 256 single-byte and all
65,536 two-byte inputs.  Recreate the compact data from that evidence with::

    .venv/bin/python proxy/tools/generate_export_big5.py \
        --comparison /path/to/big5-comparison-full.json --write
    .venv/bin/python proxy/tools/generate_export_big5.py --check

This helper validates the CPython side of every recorded difference without
embedding or invoking a Python runtime in the proxy.  The backend side is
produced by the pinned encoding_rs probe described in the evidence report.
"""

import argparse
import json
from pathlib import Path

OUTPUT = Path(__file__).with_name("export_big5_corrections.json")
PYTHON_VERSION = "3.12.14"
ENCODING_RS_VERSION = "0.8.41"
COMPARISON_SHA256 = "0988787bca646a157c6b0cf1a1f8d3aeca0605be3273be22c958fab457569833"
COMPARISON_COUNTS = {
    "single_byte_inputs": 256,
    "two_byte_inputs": 65536,
    "compared": 65792,
    "python_valid": 30222,
    "differences": 5144,
}


def python_value(hex_bytes: str) -> str:
    try:
        text = bytes.fromhex(hex_bytes).decode("big5")
    except UnicodeDecodeError:
        return "ERROR"
    return "".join(f"{ord(character):X}" for character in text)


def compact(comparison: dict) -> dict:
    if comparison.get("codec") != "big5":
        raise ValueError("comparison is not for Big5")
    for key, value in COMPARISON_COUNTS.items():
        if comparison.get(key) != value:
            raise ValueError(f"unexpected Big5 comparison {key}")
    differences = comparison.get("differences_full")
    if not isinstance(differences, list) or len(differences) != COMPARISON_COUNTS["differences"]:
        raise ValueError("complete Big5 difference list is missing")
    corrections = []
    for difference in differences:
        hex_bytes = difference.get("hex")
        source_value = difference.get("python")
        if not isinstance(hex_bytes, str) or source_value != python_value(hex_bytes):
            raise ValueError(f"CPython mismatch for Big5 input {hex_bytes!r}")
        if difference.get("encoding_rs") == source_value:
            raise ValueError(f"not a backend difference for Big5 input {hex_bytes!r}")
        if source_value != "ERROR":
            corrections.append({"bytes": hex_bytes, "codepoint": f"U+{source_value}"})
    if len(corrections) != 260:
        raise ValueError("unexpected number of Big5 mapping corrections")
    corrections.sort(key=lambda item: item["bytes"])
    return {
        "source": {
            "python": PYTHON_VERSION,
            "codec": "big5",
            "license": "Python Software Foundation License 2.0",
            "comparison_sha256": COMPARISON_SHA256,
            "compared": COMPARISON_COUNTS["compared"],
            "python_valid": COMPARISON_COUNTS["python_valid"],
            "backend_differences": COMPARISON_COUNTS["differences"],
            "mapping_corrections": len(corrections),
        },
        "encoding_rs": ENCODING_RS_VERSION,
        "corrections": corrections,
    }


def validate_provenance(source: object, encoding_rs: object) -> None:
    if not isinstance(source, dict) or source.get("python") != PYTHON_VERSION:
        raise ValueError("unexpected CPython Big5 provenance")
    if (
        source.get("codec") != "big5"
        or source.get("license") != "Python Software Foundation License 2.0"
        or source.get("comparison_sha256") != COMPARISON_SHA256
    ):
        raise ValueError("unexpected Big5 comparison provenance")
    if encoding_rs != ENCODING_RS_VERSION:
        raise ValueError("unexpected encoding_rs provenance")
    for key, value in {
        "compared": COMPARISON_COUNTS["compared"],
        "python_valid": COMPARISON_COUNTS["python_valid"],
        "backend_differences": COMPARISON_COUNTS["differences"],
        "mapping_corrections": 260,
    }.items():
        if source.get(key) != value:
            raise ValueError(f"unexpected Big5 provenance {key}")


def validate_corrections(corrections: object) -> None:
    if not isinstance(corrections, list) or len(corrections) != 260:
        raise ValueError("unexpected Big5 correction count")
    if corrections != sorted(corrections, key=lambda item: item["bytes"]):
        raise ValueError("Big5 corrections are not sorted")
    for correction in corrections:
        hex_bytes = correction.get("bytes")
        codepoint = correction.get("codepoint")
        if not isinstance(hex_bytes, str) or not isinstance(codepoint, str):
            raise ValueError("malformed Big5 correction")
        expected = python_value(hex_bytes)
        if expected == "ERROR" or codepoint != f"U+{expected}":
            raise ValueError(f"CPython mismatch for Big5 correction {hex_bytes!r}")


def validate_data(data: dict) -> None:
    source = data.get("source")
    validate_provenance(source, data.get("encoding_rs"))
    validate_corrections(data.get("corrections"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--comparison", type=Path)
    args = parser.parse_args()
    if args.write:
        if args.comparison is None:
            parser.error("--write requires --comparison")
        data = compact(json.loads(args.comparison.read_text()))
        OUTPUT.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n")
        print(f"wrote {OUTPUT} ({len(data['corrections'])} corrections)")
    else:
        data = json.loads(OUTPUT.read_text())
        validate_data(data)
        print(f"matched {OUTPUT} ({len(data['corrections'])} corrections)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
