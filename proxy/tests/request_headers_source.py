"""Refresh/check inert header fixtures with actual Headers/RequestIdGenerator.

Run from the main source environment with --check, or --write to regenerate.
The 27 frozen_parser input rows originate in the separately frozen actual H1/H2
metadata proof; this program does not replace either HTTP parser. Additional
rows exercise the actual source header hook. No regex or credential detection
is invoked. All values are synthetic and safe to persist.
"""

import argparse
import hashlib
import json
import sys
import unicodedata
from pathlib import Path

from mitmproxy.http import Headers
from mitmproxy.test.tflow import tflow

from safeyolo.mitm_addons import request_id


def header_view(headers):
    return [
        [
            name.encode("utf-8", "surrogateescape").hex(),
            value.encode("utf-8", "surrogateescape").hex(),
        ]
        for name, value in dict(headers).items()
    ]


def source_row(row):
    headers = Headers([(bytes.fromhex(name), bytes.fromhex(value)) for name, value in row["fields"]])
    flow = tflow()
    flow.request.headers = headers
    flow.metadata["request_id"] = "req-" + "1" * 32
    grouped = header_view(headers)
    request_id.RequestIdGenerator().request(flow)
    return {
        **{key: row[key] for key in ("id", "kind", "protocol", "fields")},
        "grouped": grouped,
        "after_hygiene": header_view(headers),
        "trace": flow.metadata.get("trace", False),
        "websocket": flow.metadata.get("is_websocket", False),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    fixture = Path(__file__).with_suffix(".json")
    old = json.loads(fixture.read_text())
    lower_ascii = [[scalar, chr(scalar).lower()] for scalar in range(128, 0x110000) if chr(scalar).lower().isascii()]
    assert lower_ascii == [[0x212A, "k"]]
    result = {
        "source": {
            "python": sys.version.split()[0],
            "unicode": unicodedata.unidata_version,
            "request_id_sha256": hashlib.sha256(Path(request_id.__file__).read_bytes()).hexdigest(),
        },
        "lower_to_ascii": lower_ascii,
        "python_whitespace": [scalar for scalar in range(0x110000) if chr(scalar).isspace()],
        "rows": [source_row(row) for row in old["rows"]],
    }
    if args.write:
        fixture.write_text(json.dumps(result, indent=2) + "\n")
    else:
        assert result == old, "actual source header contract changed"
    print(json.dumps({"rows": len(result["rows"]), "source": result["source"]}))


if __name__ == "__main__":
    main()
