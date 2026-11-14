#!/usr/bin/env python3
"""Prepare exact-output publication fields; perform no Coord mutation."""

import argparse
import base64
import hashlib
import json
from pathlib import Path


def publication(path: Path) -> dict:
    """Bind the retained artifact bytes to the native SHA-256 reference."""
    value = path.read_bytes()
    return {"target_ref": "sha256:" + hashlib.sha256(value).hexdigest(),
            "artifact_base64": base64.b64encode(value).decode()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    print(json.dumps(publication(parser.parse_args().artifact)))
