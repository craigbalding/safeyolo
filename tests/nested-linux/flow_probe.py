#!/usr/bin/env python3
"""Exercise nested HTTPS and verify agent-scoped flow attribution."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from urllib.parse import quote


def curl(*args: str, header_input: str | None = None) -> str:
    result = subprocess.run(
        ["curl", "-fsS", *args],
        input=header_input,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"curl failed ({result.returncode}): {result.stderr[-1000:]}")
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True)
    parser.add_argument("--target", default="https://example.com/")
    args = parser.parse_args()

    token = Path("/app/agent_token").read_text().strip()
    authorization = f"Authorization: Bearer {token}\n"
    health = json.loads(
        curl(
            "--header",
            "@-",
            "http://_safeyolo.proxy.internal/health",
            header_input=authorization,
        )
    )
    if health.get("status") != "ok" and health.get("agent_api") != "ok":
        raise SystemExit(f"nested Agent API health failed: {health}")

    body = curl(
        "-H",
        f"X-SafeYolo-Test-Context: run=nested-linux-acceptance;agent={args.agent}",
        args.target,
    )
    if not body:
        raise SystemExit("nested HTTPS response was empty")

    host = args.target.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    search_url = f"http://_safeyolo.proxy.internal/api/flows/search?host={quote(host)}&limit=20"
    matching = []
    flows = []
    for _attempt in range(20):
        payload = json.loads(
            curl("--header", "@-", search_url, header_input=authorization)
        )
        flows = payload.get("flows", [])
        matching = [
            flow
            for flow in flows
            if flow.get("host") == host and flow.get("agent_id") == args.agent
        ]
        if matching:
            break
        time.sleep(0.1)
    if not matching:
        raise SystemExit(
            f"no {host} flow attributed to {args.agent}: {[(flow.get('host'), flow.get('agent_id')) for flow in flows]}"
        )
    print(f"nested HTTPS and flow attribution: ok (flow {matching[0].get('id')})")


if __name__ == "__main__":
    main()
