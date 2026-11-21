"""A typed HTTP-status finding. This is not independent source capture."""

import json
from pathlib import Path

from safeyolo_proxy import open_url


def check(request):
    """Accept policy-owned string inputs and equivalent direct-job JSON inputs."""
    inputs = request.get("inputs", {})
    expected = inputs.get("expected_status", "200")
    if isinstance(expected, str):
        expected = int(expected)
    elif type(expected) is not int:
        raise ValueError("expected_status must be an unsigned decimal status")
    if not 0 <= expected <= 65535:
        raise ValueError("expected_status exceeds the client's status type")
    url = inputs.get("url") or request["subject"]["value"]
    with open_url(url, service=inputs.get("service")) as response:
        positive = response.status == expected
    return {"finding": {"kind": "finding", "positive": positive}}


def main():
    print(json.dumps(check(json.loads(Path("/input/request.json").read_bytes()))))


if __name__ == "__main__":
    main()
