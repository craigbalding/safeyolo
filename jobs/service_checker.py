"""GitHub issue-author predicate using the supported Unikraft host-call API.

Only the adopted inputs select the repository and expected stable author ID.
The host supplies authority, captured-byte identity, execution identity and time.
"""

import base64
import json
import sys
from pathlib import Path

MAX_CAPTURE = 1024 * 1024
CHUNK = 16 * 1024


def decimal(value):
    if not isinstance(value, str) or not value or any(char not in "0123456789" for char in value):
        raise ValueError("issue and author IDs must be unsigned decimal integers")
    result = int(value)
    if result > 2**64 - 1:
        raise ValueError("issue or author ID exceeds u64")
    return result


def service_check(request, call):
    """Read the complete bounded capture before evaluating the author."""
    subject = request["subject"]
    number = decimal(subject["value"])
    if subject["kind"] != "value" or number <= 0:
        raise ValueError("subject must be a positive issue number")
    inputs = request["inputs"]
    author = decimal(inputs["expected_author_id"])
    url = f"https://api.github.com/repos/{inputs['repository']}/issues/{number}"
    response = call({"kind": "service", "service": "github", "method": "GET", "url": url})
    size = response["bytes"]
    if type(size) is not int or not 0 <= size <= MAX_CAPTURE or response["status"] != 200:
        raise ValueError("capture is missing, oversized or not HTTP 200")
    capture = bytearray()
    while len(capture) < size:
        chunk = call({"kind": "read", "id": response["id"], "offset": len(capture), "length": CHUNK})
        if chunk["total_bytes"] != size:
            raise ValueError("capture size changed")
        data = base64.b64decode(chunk["data_base64"], validate=True)
        if not data or len(data) > min(CHUNK, size - len(capture)):
            raise ValueError("capture chunk is empty or exceeds remaining bytes")
        capture.extend(data)
    evidence = json.loads(capture)
    if (evidence.get("url") != url or type(evidence.get("number")) is not int
            or evidence["number"] != number or type(evidence.get("id")) is not int
            or not isinstance(evidence.get("title"), str) or not isinstance(evidence.get("updated_at"), str)):
        raise ValueError("GitHub evidence subject or required metadata mismatch")
    actual_author = evidence["user"]["id"]
    if type(actual_author) is not int:
        raise ValueError("GitHub author ID unavailable")
    if not 0 <= actual_author <= 2**64 - 1 or not 0 <= evidence["id"] <= 2**64 - 1:
        raise ValueError("GitHub ID exceeds u64")
    return {"finding": {"kind": "finding", "positive": actual_author == author}}


def main():
    import hyperlight

    request = json.loads(Path("/input/request.json").read_bytes())

    def call(value):
        reply = hyperlight.call("sy.call", value)
        if reply["ok"] is not True:
            raise RuntimeError(reply.get("error", "service call failed"))
        return reply["value"]

    if "--isolation-probe" in sys.argv:
        import os
        import socket

        def unavailable(operation):
            try:
                operation()
            except OSError as error:
                return {"unavailable": True, "error": str(error)}
            return {"unavailable": False}

        def connect():
            with socket.socket() as stream:
                stream.settimeout(1)
                stream.connect(("127.0.0.1", request["port"]))

        result = {"socket": unavailable(connect),
                  "dns": unavailable(lambda: socket.getaddrinfo("api.github.com", 443)),
                  "credentials_absent": not any(name in os.environ for name in
                                                ("SAFEYOLO_GATEWAY_TOKENS", "GITHUB_TOKEN", "GH_TOKEN")),
                  "host_tokens_absent": not any(Path(name).exists() for name in
                                                ("/app/agent_token", "/safeyolo/agent_token"))}
    elif "--probe" in sys.argv:
        result = [hyperlight.call("sy.call", request["call"]) for _ in range(request.get("repeat", 1))]
    else:
        result = service_check(request, call)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
