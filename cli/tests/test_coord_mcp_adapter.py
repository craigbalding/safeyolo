"""Compatibility contracts for the standalone coord MCP adapter."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path


class _MCPServer:
    def __init__(self, _name):
        pass

    def tool(self):
        return lambda function: function

    def run(self):
        pass


def _load_adapter(monkeypatch):
    mcp_package = types.ModuleType("mcp")
    server_package = types.ModuleType("mcp.server")
    server_module = types.ModuleType("mcp.server.mcpserver")
    server_module.MCPServer = _MCPServer
    monkeypatch.setitem(sys.modules, "mcp", mcp_package)
    monkeypatch.setitem(sys.modules, "mcp.server", server_package)
    monkeypatch.setitem(sys.modules, "mcp.server.mcpserver", server_module)

    path = Path(__file__).resolve().parents[2] / "contrib/safeyolo-coord-mcp.py"
    spec = importlib.util.spec_from_file_location("coord_mcp_adapter_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_send_explicitly_defaults_to_no_attention(monkeypatch):
    module = _load_adapter(monkeypatch)
    calls = []

    async def post(path, body):
        calls.append((path, body))
        return {"ok": True}

    monkeypatch.setattr(module, "_post", post)
    asyncio.run(module.send("room", "body"))
    assert calls == [
        (
            "/api/coord/rooms/room/send",
            {
                "body": "body",
                "declared_content_type": "text/markdown",
                "notify": "none",
            },
        )
    ]


def test_attention_tools_use_identity_derived_routes(monkeypatch):
    module = _load_adapter(monkeypatch)
    calls = []

    async def get(path, params=None, *, timeout=60.0):
        calls.append((path, params, timeout))
        return {"ok": True}

    monkeypatch.setattr(module, "_get", get)
    asyncio.run(
        module.wait_for_attention(
            since_sequence=7, timeout_seconds=12.0, limit=3
        )
    )
    asyncio.run(module.read_attention("attn-" + "a" * 32))
    assert calls == [
        (
            "/api/coord/attention/wait",
            {"since": 7, "timeout": 12.0, "limit": 3},
            22.0,
        ),
        ("/api/coord/attention/attn-" + "a" * 32 + "/object", None, 60.0),
    ]


def test_tool_descriptions_guide_the_targeted_multi_room_workflow(monkeypatch):
    module = _load_adapter(monkeypatch)
    wait_for_message_doc = " ".join((module.wait_for_message.__doc__ or "").split())

    assert "Primary identity-derived multiplexed coordination wait" in (
        module.wait_for_attention.__doc__ or ""
    )
    assert "Normal next operation after an attention wake" in (
        module.read_attention.__doc__ or ""
    )
    assert "Explicit retained room history, context, and catch-up" in (
        module.read_room.__doc__ or ""
    )
    assert "Legacy per-room compatibility" in (
        module.wait_for_message.__doc__ or ""
    )
    assert "not the normal targeted multi-room coordination workflow" in (
        wait_for_message_doc
    )
