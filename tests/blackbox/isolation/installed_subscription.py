"""Act as a synthetic Codex client inside a real installed test guest.

The fixture deliberately provisions this login. Renewal is a client operation;
the proxy must recognize replacements without giving another guest authority.
Only status and token fingerprints leave this process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ssl
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

LOGIN = Path("/home/agent/.codex/bb-subscription.json")


def attempt(operation: str, marker: str) -> dict:
    tokens = json.loads(LOGIN.read_text())["tokens"]
    headers = {"X-Probe-Marker": marker, "Content-Type": "application/json"}
    if operation == "refresh":
        url = "https://auth.openai.com/oauth/token"
        body = {"grant_type": "refresh_token", "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
                "refresh_token": tokens["refresh_token"]}
    else:
        url = "https://chatgpt.com/backend-api/codex/responses"
        headers["Authorization"] = "Bearer " + tokens["access_token"]
        body = {}
    request = Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    context = ssl.create_default_context(cafile="/usr/local/share/ca-certificates/safeyolo.crt")
    try:
        response = urlopen(request, context=context, timeout=12)
    except HTTPError as error:
        response = error
    with response:
        payload = response.read(65537)
        assert len(payload) <= 65536, "synthetic provider response exceeded its bound"
        status = response.code
    if operation == "refresh" and status == 200:
        refreshed = json.loads(payload)
        assert isinstance(refreshed.get("access_token"), str) and isinstance(refreshed.get("refresh_token"), str)
        tokens.update(refreshed)
        LOGIN.write_text(json.dumps({"auth_mode": "chatgpt", "tokens": tokens}))
        LOGIN.chmod(0o600)
    return {"status": status, "operation": operation,
            "token_fingerprints": {key: hashlib.sha256(value.encode()).hexdigest() for key, value in tokens.items()}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("access", "refresh"))
    parser.add_argument("marker")
    args = parser.parse_args()
    print("SUBSCRIPTION=" + json.dumps(attempt(args.operation, args.marker)), flush=True)
