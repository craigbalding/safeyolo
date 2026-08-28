"""Compatibility contracts for the standalone coord MCP adapter."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path

import pytest


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


def test_wait_for_coord_resolves_the_whole_page_before_returning_cursor(monkeypatch):
    module = _load_adapter(monkeypatch)
    calls = []
    attention_ids = ["attn-" + "a" * 32, "attn-" + "b" * 32]

    async def get(path, params=None, *, timeout=60.0):
        calls.append((path, params, timeout))
        if path == "/api/coord/attention/wait":
            return {
                "edges": [
                    {"attention_id": attention_ids[0]},
                    {"attention_id": attention_ids[1]},
                ],
                "next_cursor": 9,
            }
        return {"object": {"attention_id": path.split("/")[-2]}}

    monkeypatch.setattr(module, "_get", get)
    result = asyncio.run(
        module.wait_for_coord(since_sequence=7, timeout_seconds=12.0, limit=2)
    )

    assert result == {
        "objects": [
            {"object": {"attention_id": attention_ids[0]}},
            {"object": {"attention_id": attention_ids[1]}},
        ],
        "next_cursor": 9,
    }
    assert calls == [
        (
            "/api/coord/attention/wait",
            {"since": 7, "timeout": 12.0, "limit": 2},
            22.0,
        ),
        (f"/api/coord/attention/{attention_ids[0]}/object", None, 60.0),
        (f"/api/coord/attention/{attention_ids[1]}/object", None, 60.0),
    ]


def test_wait_for_coord_does_not_return_cursor_after_partial_resolution(monkeypatch):
    module = _load_adapter(monkeypatch)
    attention_ids = ["attn-" + "a" * 32, "attn-" + "b" * 32]
    resolved = []

    async def get(path, params=None, *, timeout=60.0):
        if path == "/api/coord/attention/wait":
            return {
                "edges": [{"attention_id": item} for item in attention_ids],
                "next_cursor": 9,
            }
        if attention_ids[1] in path:
            raise RuntimeError("canonical object unavailable")
        resolved.append(path)
        return {"object": {"ok": True}}

    monkeypatch.setattr(module, "_get", get)

    with pytest.raises(RuntimeError, match="canonical object unavailable"):
        asyncio.run(module.wait_for_coord(since_sequence=7, limit=2))

    assert resolved == [f"/api/coord/attention/{attention_ids[0]}/object"]


def test_tool_descriptions_guide_the_targeted_multi_room_workflow(monkeypatch):
    module = _load_adapter(monkeypatch)
    wait_for_message_doc = " ".join((module.wait_for_message.__doc__ or "").split())

    assert "Lower-level identity-derived multiplexed attention wait" in (
        module.wait_for_attention.__doc__ or ""
    )
    assert "Primary foreground idle wait" in (module.wait_for_coord.__doc__ or "")
    assert "resolution failure fails" in (module.wait_for_coord.__doc__ or "")
    assert "Lower-level resolution operation" in (
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
