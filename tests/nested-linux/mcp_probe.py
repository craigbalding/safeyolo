#!/usr/bin/env python3
"""Prove that the bundled coord MCP launcher completes an MCP handshake."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

LAUNCHER = Path("/home/agent/.safeyolo/safeyolo-coord-mcp-launcher")


def main() -> None:
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "nested-linux-acceptance", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    payload = "".join(json.dumps(message) + "\n" for message in messages)
    result = subprocess.run(
        [str(LAUNCHER)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"coord MCP launcher failed ({result.returncode}): {result.stderr[-1000:]}")
    responses = [json.loads(line) for line in result.stdout.splitlines() if line]
    initialize = next((item for item in responses if item.get("id") == 1), None)
    tools = next((item for item in responses if item.get("id") == 2), None)
    if not initialize or "result" not in initialize:
        raise SystemExit("coord MCP initialize response is missing")
    tool_names = {item.get("name") for item in (tools or {}).get("result", {}).get("tools", [])}
    required = {"join_room", "send", "wait_for_coord"}
    if not required.issubset(tool_names):
        raise SystemExit(f"coord MCP tools missing: {sorted(required - tool_names)}")
    print("coord MCP handshake and bundled tools: ok")


if __name__ == "__main__":
    main()
