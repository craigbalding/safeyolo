#!/usr/bin/env python3
"""Prove that the bundled coord MCP launcher reaches the coord backend."""

from __future__ import annotations

import argparse
import json
import select
import subprocess
import time
from pathlib import Path
from typing import Any, TextIO

LAUNCHER = Path("/home/agent/.safeyolo/safeyolo-coord-mcp-launcher")


def send(stream: TextIO, message: dict[str, Any]) -> None:
    stream.write(json.dumps(message) + "\n")
    stream.flush()


def read_response(
    process: subprocess.Popen[str], response_id: int, *, timeout: float = 30
) -> dict[str, Any]:
    if process.stdout is None:
        raise SystemExit("coord MCP stdout is unavailable")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select(
            [process.stdout], [], [], max(0, deadline - time.monotonic())
        )
        if not ready:
            break
        line = process.stdout.readline()
        if not line:
            raise SystemExit("coord MCP launcher closed before responding")
        response = json.loads(line)
        if response.get("id") == response_id:
            return response
    raise SystemExit(f"coord MCP response {response_id} timed out")


def structured_result(response: dict[str, Any]) -> dict[str, Any]:
    if "error" in response:
        raise SystemExit(f"coord MCP tools/call failed: {response['error']}")
    result = response.get("result")
    if not isinstance(result, dict) or result.get("isError") is True:
        raise SystemExit(f"coord MCP tools/call returned an error: {result}")
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured
    for item in result.get("content", []):
        if item.get("type") == "text":
            value = json.loads(item.get("text", ""))
            if isinstance(value, dict):
                return value
    raise SystemExit("coord MCP tools/call returned no structured result")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--room", required=True)
    args = parser.parse_args()

    process = subprocess.Popen(
        [str(LAUNCHER)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    if process.stdin is None:
        raise SystemExit("coord MCP stdin is unavailable")
    try:
        send(
            process.stdin,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "nested-linux-acceptance",
                        "version": "1",
                    },
                },
            },
        )
        initialize = read_response(process, 1)
        if "result" not in initialize:
            raise SystemExit("coord MCP initialize response is missing")
        send(
            process.stdin,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        send(
            process.stdin,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        tools = read_response(process, 2)
        tool_names = {
            item.get("name") for item in tools.get("result", {}).get("tools", [])
        }
        required = {"join_room", "send", "wait_for_coord"}
        if not required.issubset(tool_names):
            raise SystemExit(f"coord MCP tools missing: {sorted(required - tool_names)}")

        send(
            process.stdin,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "join_room",
                    "arguments": {"room_name": args.room},
                },
            },
        )
        joined = structured_result(read_response(process, 3))
        if joined.get("room_name") != args.room:
            raise SystemExit(f"coord MCP joined an unexpected room: {joined}")
        permissions = set(joined.get("permissions", []))
        if not {"send", "receive"}.issubset(permissions):
            raise SystemExit(f"coord MCP room permissions are incomplete: {joined}")
    finally:
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)

    if process.returncode != 0:
        stderr = process.stderr.read() if process.stderr else ""
        raise SystemExit(
            f"coord MCP launcher failed ({process.returncode}): {stderr[-1000:]}"
        )
    print(f"coord MCP backend join: ok (room {args.room})")


if __name__ == "__main__":
    main()
