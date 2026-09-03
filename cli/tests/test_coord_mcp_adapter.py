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


def test_send_task_builds_one_header_and_notifies_only_exact_assignee(monkeypatch):
    module = _load_adapter(monkeypatch)
    calls = []

    async def post(path, body):
        calls.append((path, body))
        return {
            "envelope": {"msg_id": "msg-" + "a" * 32},
            "sequence": 41,
        }

    monkeypatch.setattr(module, "_post", post)
    result = asyncio.run(
        module.send_task(
            "backlog",
            "forge",
            "issue-469",
            "Preserve this paragraph.\n\n- and this list",
        )
    )

    assert result == {
        "envelope": {"msg_id": "msg-" + "a" * 32},
        "sequence": 41,
    }
    assert len(calls) == 1
    assert calls == [
        (
            "/api/coord/rooms/backlog/send",
            {
                "body": (
                    "TASK task=issue-469 assignee=forge\n\n"
                    "Preserve this paragraph.\n\n- and this list"
                ),
                "declared_content_type": "text/markdown",
                "notify": ["forge"],
            },
        )
    ]


@pytest.mark.parametrize(
    ("room", "assignee", "task_id", "body", "message"),
    [
        ("", "forge", "issue-469", "work", "room_name"),
        ("backlog", "", "issue-469", "work", "assignee"),
        ("backlog", "forge extra", "issue-469", "work", "assignee"),
        ("backlog", "forge", "issue 469", "work", "task_id"),
        ("backlog", "forge", "issue-469", " \n", "body is missing"),
        (
            "backlog",
            "forge",
            "issue-469",
            "TASK task=other assignee=forge\n\nduplicate",
            "duplicate TASK header",
        ),
    ],
)
def test_send_task_rejects_missing_malformed_or_duplicate_fields(
    monkeypatch, room, assignee, task_id, body, message
):
    module = _load_adapter(monkeypatch)

    async def unexpected_post(*_args, **_kwargs):
        raise AssertionError("invalid task must not be sent")

    monkeypatch.setattr(module, "_post", unexpected_post)
    with pytest.raises(ValueError, match=message):
        asyncio.run(module.send_task(room, assignee, task_id, body))


@pytest.mark.parametrize(
    "body",
    [
        "Return DONE task=issue-469 after validation.",
        "Explain why assignee=forge is the configured owner.",
        "A malformed example such as assignee = is ordinary explanatory text.",
    ],
)
def test_send_task_allows_field_like_text_below_the_canonical_header(monkeypatch, body):
    module = _load_adapter(monkeypatch)
    calls = []

    async def post(path, payload):
        calls.append((path, payload))
        return {"envelope": {"msg_id": "msg-" + "a" * 32}, "sequence": 41}

    monkeypatch.setattr(module, "_post", post)
    asyncio.run(module.send_task("backlog", "forge", "issue-469", body))

    assert calls[0][1]["body"] == f"TASK task=issue-469 assignee=forge\n\n{body}"


def test_send_task_requires_canonical_sequence(monkeypatch):
    module = _load_adapter(monkeypatch)

    async def post(_path, _body):
        return {
            "envelope": {"msg_id": "msg-" + "a" * 32, "sequence": 41},
        }

    monkeypatch.setattr(module, "_post", post)
    with pytest.raises(RuntimeError, match="canonical room sequence"):
        asyncio.run(module.send_task("backlog", "forge", "issue-469", "work"))


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


def test_read_brief_uses_authorized_canonical_route(monkeypatch):
    module = _load_adapter(monkeypatch)
    calls = []

    async def get(path, params=None, *, timeout=60.0):
        calls.append((path, params, timeout))
        return {"revision": 5, "markdown": "# trusted"}

    monkeypatch.setattr(module, "_get", get)
    result = asyncio.run(module.read_brief("huddle"))

    assert result == {"revision": 5, "markdown": "# trusted"}
    assert calls == [
        ("/api/coord/rooms/huddle/brief", None, 60.0),
    ]


def test_inventory_tools_use_authorized_identity_derived_routes(monkeypatch):
    module = _load_adapter(monkeypatch)
    calls = []

    async def get(path, params=None, *, timeout=60.0):
        calls.append(("GET", path, params, timeout))
        return {"members": []}

    async def post(path, body):
        calls.append(("POST", path, body, 60.0))
        return {"count": len(body["capabilities"])}

    monkeypatch.setattr(module, "_get", get)
    monkeypatch.setattr(module, "_post", post)

    assert asyncio.run(module.get_room_state("huddle")) == {"members": []}
    assert asyncio.run(
        module.declare_capabilities("huddle", ["skill:python"], 120)
    ) == {"count": 1}
    assert calls == [
        ("GET", "/api/coord/rooms/huddle/state", None, 60.0),
        (
            "POST",
            "/api/coord/rooms/huddle/declarations",
            {"capabilities": ["skill:python"], "ttl_seconds": 120},
            60.0,
        ),
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
    assert "trusted canonical operator state" in (
        module.wait_for_coord.__doc__ or ""
    )
    assert "canonical trusted operator brief" in (
        module.read_brief.__doc__ or ""
    )
    assert "current authoritative room identity" in (
        module.get_room_state.__doc__ or ""
    )
    assert "attributed but untrusted" in (
        module.declare_capabilities.__doc__ or ""
    )
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
