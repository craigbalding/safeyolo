#!/usr/bin/env python3
"""Exercise nested HTTPS and verify agent-scoped flow attribution."""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import time
from pathlib import Path
from urllib.parse import urlencode


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

    nonce = secrets.token_hex(8)
    run_id = f"nested-linux-acceptance-{nonce}"
    test_id = f"HTTPS-{nonce}"
    body = curl(
        "-H",
        (
            "X-SafeYolo-Test-Context: "
            f"run={run_id};agent={args.agent};test={test_id}"
        ),
        args.target,
    )
    if not body:
        raise SystemExit("nested HTTPS response was empty")

    host = args.target.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    filters = urlencode({"host": host, "run": run_id, "test": test_id, "limit": 20})
    search_url = f"http://_safeyolo.proxy.internal/api/flows/search?{filters}"
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
            if (
                flow.get("host") == host
                and flow.get("agent_id") == args.agent
                and flow.get("run") == run_id
                and flow.get("test") == test_id
            )
        ]
        if matching:
            break
        time.sleep(0.1)
    if not matching:
        raise SystemExit(
            f"no fresh {host} flow for {args.agent} with run={run_id} "
            f"and test={test_id}: "
            f"{[(flow.get('host'), flow.get('agent_id'), flow.get('run'), flow.get('test')) for flow in flows]}"
        )
    print(
        "nested HTTPS and fresh flow attribution: ok "
        f"(flow {matching[0].get('id')}, run {run_id}, test {test_id})"
    )


if __name__ == "__main__":
    main()
