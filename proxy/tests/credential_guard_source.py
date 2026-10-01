"""Actual source parser-to-credential-detector controls for invalid header bytes."""

import hashlib
import json
import sys
import unicodedata
from pathlib import Path

from mitmproxy.http import Headers

from safeyolo.detection.credentials import CredentialRule, analyze_headers

CASES = [
    ("authorization_ff", b"Bearer key-\xff"),
    ("authorization_fe", b"Bearer key-\xfe"),
    ("authorization_truncated_utf8", b"Bearer key-\xc3"),
]
PATTERN = r"key-\udcff"


def source_row(name: str, value: bytes) -> dict:
    parsed = Headers([(b"Authorization", value)])
    source_headers = dict(parsed)
    rule = CredentialRule(
        name="synthetic-invalid-byte",
        patterns=[PATTERN],
        allowed_hosts=["127.0.0.1"],
        header_names=["authorization"],
    )
    detections = analyze_headers(
        headers=source_headers,
        rules=[rule],
        safe_headers_config={},
        entropy_config={},
        standard_auth_headers=["authorization"],
        detection_level="standard",
    )
    detection = detections[0] if detections else None
    return {
        "id": name,
        "fields": [[b"Authorization".hex(), value.hex()]],
        "detected": detection is not None,
        "rule_name": detection["rule_name"] if detection else None,
        "header_name": detection["header_name"] if detection else None,
        "credential_bytes": list(
            detection["credential"].encode("utf-8", "surrogateescape")
        )
        if detection
        else None,
    }


def main() -> None:
    root = Path(__file__).parents[2]
    source = root / "cli/src/safeyolo/detection/credentials.py"
    result = {
        "source": {
            "python": sys.version.split()[0],
            "unicode": unicodedata.unidata_version,
            "credentials_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        },
        "pattern": PATTERN,
        "rows": [source_row(name, value) for name, value in CASES],
    }
    print(json.dumps(result, indent=2) + "\n", end="")


if __name__ == "__main__":
    main()
