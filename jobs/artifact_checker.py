"""Check the exact small JSON artifact retained with a native Work output."""

import base64
import json
from pathlib import Path


def artifact_check(request):
    """Malformed evidence fails execution; a different status is a negative finding."""
    if request["subject"]["kind"] != "value":
        raise ValueError("artifact subject must be a value")
    subject = json.loads(request["subject"]["value"])
    artifact = json.loads(base64.b64decode(subject["artifact_base64"], validate=True))
    status = artifact["status"]
    expected = request["inputs"]["expected_status"]
    if not isinstance(status, str) or not isinstance(expected, str):
        raise ValueError("artifact and expected status must be strings")
    return {"finding": {"kind": "finding", "positive": status == expected}}


if __name__ == "__main__":
    print(json.dumps(artifact_check(json.loads(Path("/input/request.json").read_bytes())), separators=(",", ":")))
