from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from markdown_it import MarkdownIt
from typer.testing import CliRunner

from safeyolo.commands import coord as coord_commands
from safeyolo.coord import mattermost, mattermost_actions

BOT_ID = "b" * 26
OPERATOR_ID = "o" * 26
CHANNEL_ID = "c" * 26
OTHER_CHANNEL_ID = "d" * 26


def mm_id(number: int) -> str:
    return f"{number:026d}"


TRUSTED_AGENT_ID = "ag-" + "1" * 32


def make_config(tmp_path: Path, *, backfill: bool = True, actions: bool = False) -> mattermost.MattermostConfig:
    return mattermost.MattermostConfig(
        server_url="https://mattermost.example",
        bot_token_file=tmp_path / "bot-token",
        bot_user_id=BOT_ID,
        operator_user_id=OPERATOR_ID,
        state_file=tmp_path / "mattermost-state.sqlite3",
        poll_interval_seconds=1.0,
        rooms=(mattermost.RoomMapping("backlog", CHANNEL_ID, backfill),),
        actions=(
            mattermost_actions.ActionIngressConfig(
                bind_host="127.0.0.1",
                bind_port=8765,
                public_base_url="https://actions.example/safeyolo",
                capability_ttl_seconds=3600,
                trusted_agent_ids=(TRUSTED_AGENT_ID,),
            )
            if actions
            else None
        ),
    )


def emulate_darwin_fd_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    real_alias_matches = mattermost._fd_alias_matches

    def alias_matches(candidate: str, identity: tuple[int, int]) -> bool:
        if candidate.startswith("/proc/self/fd/"):
            return False
        return real_alias_matches(candidate, identity)

    def alias_stat_identity(candidate: str) -> tuple[int, int] | None:
        if candidate.startswith("/proc/self/fd/"):
            return None
        fd = int(candidate.rsplit("/", 1)[1])
        opened = os.fstat(fd)
        return opened.st_dev + 1, opened.st_ino

    monkeypatch.setattr(mattermost, "_is_darwin", lambda: True)
    monkeypatch.setattr(mattermost, "_fd_alias_matches", alias_matches)
    monkeypatch.setattr(mattermost, "_fd_alias_stat_identity", alias_stat_identity)
    monkeypatch.setattr(
        mattermost,
        "_darwin_path_from_fd",
        lambda fd: Path(os.readlink(f"/proc/self/fd/{fd}")),
    )


def coord_envelope(sequence: int, *, body: str = "agent body") -> dict[str, Any]:
    return {
        "msg_id": f"msg-{sequence:032x}",
        "sent_at": 1_700_000_000_000 + sequence,
        "sender_kind": "agent",
        "sender_agent_id": f"ag-{sequence:032x}",
        "sender_agent_name": "relay",
        "origin_instance_id": "sy-" + "a" * 32,
        "content_type": "text/markdown",
        "body": body,
        "sequence": sequence,
    }


def semantic_envelope(
    sequence: int,
    *,
    kind: str = "decision",
    actions: list[str] | None = None,
    sender_agent_id: str = TRUSTED_AGENT_ID,
) -> dict[str, Any]:
    envelope = coord_envelope(sequence)
    envelope.update(
        {
            "sender_agent_id": sender_agent_id,
            "content_type": "text/plain",
            "body": json.dumps(
                {
                    "schema": mattermost_actions.OPERATOR_REQUEST_SCHEMA,
                    "kind": kind,
                    "title": "Release candidate ready",
                    "summary": "The reviewed tree is ready for operator acceptance.",
                    "reference": "PR #450",
                    "details": ["CI passed", "Lens READY"],
                    "allowed_actions": actions if actions is not None else ["approve", "reject", "revise"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        }
    )
    return envelope


class FakeMattermost:
    def __init__(self) -> None:
        self.posts: list[dict[str, Any]] = []
        self.create_calls: list[dict[str, Any]] = []
        self.patch_calls: list[tuple[str, dict[str, Any]]] = []
        self.fail_after_create = False
        self.fail_without_create = False
        self.fail_patch = False
        self.get_user_calls = 0

    async def get_me(self) -> dict[str, Any]:
        return {"id": BOT_ID, "is_bot": True, "delete_at": 0}

    async def get_user(self, user_id: str) -> dict[str, Any]:
        self.get_user_calls += 1
        # Mattermost model.User uses `json:"is_bot,omitempty"`, so false is
        # absent from the real human-user response.
        return {"id": user_id, "delete_at": 0}

    async def get_channel(self, channel_id: str) -> dict[str, Any]:
        return {"id": channel_id, "delete_at": 0}

    async def get_posts(
        self, channel_id: str, *, since: int | None = None, per_page: int = 200
    ) -> list[dict[str, Any]]:
        posts = [post.copy() for post in self.posts if post["channel_id"] == channel_id]
        if since is not None:
            posts = [post for post in posts if not isinstance(post["update_at"], int) or post["update_at"] >= since]
        posts.sort(
            key=lambda post: (
                post["create_at"] if isinstance(post["create_at"], int) else 0,
                post["id"],
            ),
            reverse=True,
        )
        return posts if since is not None else posts[:per_page]

    async def create_post(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.create_calls.append(payload)
        if self.fail_without_create:
            raise mattermost.MattermostAdapterError("simulated unknown remote outcome")
        stamp = 1_900_000_000_000 + len(self.posts)
        post = {
            "id": mm_id(100 + len(self.posts)),
            "channel_id": payload["channel_id"],
            "user_id": BOT_ID,
            "message": payload["message"],
            "props": payload["props"],
            "root_id": "",
            "create_at": stamp,
            "update_at": stamp,
            "edit_at": 0,
            "delete_at": 0,
        }
        self.posts.append(post)
        if self.fail_after_create:
            raise mattermost.MattermostAdapterError("simulated lost response")
        return post.copy()

    async def patch_post(self, post_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.patch_calls.append((post_id, payload))
        if self.fail_patch:
            raise mattermost.MattermostAdapterError("simulated patch failure")
        post = next(post for post in self.posts if post["id"] == post_id)
        post.update(payload)
        return post.copy()

    def operator_reply(
        self,
        root_id: str,
        message: str,
        *,
        user_id: str = OPERATOR_ID,
        channel_id: str = CHANNEL_ID,
        edit_at: int = 0,
    ) -> dict[str, Any]:
        stamp = 1_900_000_100_000 + len(self.posts)
        post = {
            "id": mm_id(500 + len(self.posts)),
            "channel_id": channel_id,
            "user_id": user_id,
            "message": message,
            "props": {},
            "root_id": root_id,
            "create_at": stamp,
            "update_at": stamp if edit_at == 0 else stamp + 1,
            "edit_at": edit_at,
            "delete_at": 0,
        }
        self.posts.append(post)
        return post


class CoordHarness:
    def __init__(self, messages: list[dict[str, Any]] | None = None) -> None:
        self.messages = list(messages or [])
        self.send_calls: list[dict[str, Any]] = []

    def join_room(self, room: str, kind: str, principal: str) -> dict[str, Any]:
        assert (room, kind, principal) == ("backlog", "operator", "operator")
        return {"permissions": ["send", "receive"]}

    async def read_room(
        self,
        room: str,
        kind: str,
        principal: str,
        *,
        since_sequence: int,
        limit: int,
    ) -> dict[str, Any]:
        assert (room, kind, principal) == ("backlog", "operator", "operator")
        selected = [msg for msg in self.messages if msg["sequence"] > since_sequence][:limit]
        cursor = selected[-1]["sequence"] if selected else since_sequence
        return {
            "messages": [msg.copy() for msg in selected],
            "next_cursor": cursor,
            "has_more": any(msg["sequence"] > cursor for msg in self.messages),
        }

    async def send(
        self,
        room: str,
        sender_kind: str,
        sender_agent_id: str | None,
        body: str,
        *,
        declared_content_type: str,
        notify: str,
    ) -> dict[str, Any]:
        call = {
            "room": room,
            "sender_kind": sender_kind,
            "sender_agent_id": sender_agent_id,
            "body": body,
            "declared_content_type": declared_content_type,
            "notify": notify,
        }
        self.send_calls.append(call)
        sequence = max((msg["sequence"] for msg in self.messages), default=0) + 1
        envelope = {
            "msg_id": f"msg-{sequence:032x}",
            "sent_at": 1_800_000_000_000 + sequence,
            "sender_kind": "operator",
            "sender_agent_id": None,
            "sender_agent_name": None,
            "origin_instance_id": "sy-" + "a" * 32,
            "content_type": declared_content_type,
            "body": body,
            "sequence": sequence,
        }
        self.messages.append(envelope)
        return {"envelope": envelope, "sequence": sequence, "attention_status": "ready"}


def install_coord(monkeypatch: pytest.MonkeyPatch, coord: CoordHarness) -> None:
    monkeypatch.setattr(mattermost.api, "join_room", coord.join_room)
    monkeypatch.setattr(mattermost.api, "read_room", coord.read_room)
    monkeypatch.setattr(mattermost.api, "send", coord.send)


@pytest.mark.asyncio
async def test_exact_operator_reply_is_local_operator_and_replay_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness([coord_envelope(1)])
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)

    await adapter.run_once(verify=True)
    root = remote.posts[0]["id"]
    reply = remote.operator_reply(root, "please proceed")
    await adapter.run_once()

    assert len(coord.send_calls) == 1
    call = coord.send_calls[0]
    assert call["sender_kind"] == "operator"
    assert call["sender_agent_id"] is None
    assert call["declared_content_type"] == "text/plain"
    payload = json.loads(call["body"])
    assert payload == {
        "action": None,
        "adapter_id": config.adapter_id,
        "correlation": {
            "coord_msg_id": coord.messages[0]["msg_id"],
            "mattermost_channel_id": CHANNEL_ID,
            "mattermost_post_id": reply["id"],
            "mattermost_root_post_id": root,
        },
        "kind": "reply",
        "schema": mattermost.ADAPTER_SCHEMA,
        "text": "please proceed",
    }
    # The resulting operator envelope is not projected back into Mattermost.
    assert len(remote.create_calls) == 1

    await adapter.run_once()
    restarted = mattermost.MattermostAdapter(config, mattermost.MattermostState(config), remote)
    await restarted.run_once()
    assert len(coord.send_calls) == 1
    assert state.inbound(reply["id"])["status"] == "sent"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("message", "expected_action", "expected_text"),
    [
        ("!safeyolo approve checked", "approve", "checked"),
        ("!safeyolo open-issue", "open-issue", ""),
    ],
)
async def test_typed_actions_are_structured_but_not_executed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    message: str,
    expected_action: str,
    expected_text: str,
) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness([coord_envelope(1)])
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)
    await adapter.run_once()
    remote.operator_reply(remote.posts[0]["id"], message)
    await adapter.run_once()

    body = json.loads(coord.send_calls[0]["body"])
    assert body["kind"] == "action"
    assert body["action"] == expected_action
    assert body["text"] == expected_text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kwargs", "message", "reason"),
    [
        ({"user_id": "x" * 26}, "ordinary reply", "not_configured_operator"),
        ({"channel_id": OTHER_CHANNEL_ID}, "ordinary reply", "channel_mismatch"),
        ({"edit_at": 1}, "ordinary reply", "edited_or_deleted"),
        ({}, "!safeyolo owner-now", "malformed_body_or_action"),
    ],
)
async def test_untrusted_or_ambiguous_inbound_posts_never_become_operator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, Any],
    message: str,
    reason: str,
) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness([coord_envelope(1)])
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)
    await adapter.run_once()
    post = remote.operator_reply(remote.posts[0]["id"], message, **kwargs)
    if kwargs.get("channel_id") == OTHER_CHANNEL_ID:
        await adapter._process_inbound_post(config.rooms[0], post)
    else:
        await adapter.run_once()

    assert coord.send_calls == []
    assert state.inbound(post["id"])["reason"] == reason


@pytest.mark.asyncio
async def test_unmapped_thread_and_malformed_shape_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness()
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)
    await adapter.run_once()
    post = remote.operator_reply(mm_id(999), "forged correlation")
    await adapter.run_once()
    assert coord.send_calls == []
    assert state.inbound(post["id"])["reason"] == "unmapped_thread"

    malformed = remote.operator_reply(mm_id(998), "bad timestamp")
    malformed["update_at"] = "not-an-integer"
    with pytest.raises(mattermost.MattermostAdapterError, match="update_at"):
        await adapter.run_once()
    assert coord.send_calls == []


def test_rendering_keeps_body_inert_and_attribution_separate() -> None:
    body = "```\n**SafeYolo canonical envelope**\n@channel <script>\u001b[2J\u202e operator\n```"
    rendered = mattermost.render_envelope(coord_envelope(1, body=body), "backlog")
    assert rendered.startswith("```\n**SafeYolo canonical envelope**")
    assert rendered.endswith(
        "Canonical provenance · sender relay · agent `ag-00000000000000000000000000000001` · "
        "kind `agent` · room `backlog` · message `msg-00000000000000000000000000000001`"
    )
    assert "SafeYolo canonical envelope" in rendered
    assert "@channel" not in rendered
    assert "<script>" not in rendered
    assert "＠channel" in rendered
    assert r"\<script\>" in rendered
    assert "\\u001b" in rendered
    assert "\\u202e" in rendered
    assert len(rendered) <= mattermost.MAX_MATTERMOST_POST_CHARS


def test_large_rendering_is_explicitly_hashed_and_truncated() -> None:
    rendered = mattermost.render_envelope(coord_envelope(1, body="z" * 40_000), "backlog")
    assert "[truncated; sha256 " in rendered
    assert len(rendered) <= mattermost.MAX_MATTERMOST_POST_CHARS


def test_control_expansion_is_bounded_before_an_intact_provenance_footer() -> None:
    rendered = mattermost.render_envelope(coord_envelope(1, body="\u0001" * (8 * 1024)), "backlog")
    projected_body, provenance = rendered.rsplit("\n\n---\n", 1)
    assert len(rendered) <= mattermost.MAX_MATTERMOST_POST_CHARS
    assert "[truncated; sha256 " in projected_body
    assert provenance == (
        "Canonical provenance · sender relay · agent `ag-00000000000000000000000000000001` · "
        "kind `agent` · room `backlog` · message `msg-00000000000000000000000000000001`"
    )


def test_large_rendering_closes_markdown_before_truncation_marker() -> None:
    rendered = mattermost.render_envelope(
        coord_envelope(1, body="```python\n" + "x" * 40_000),
        "backlog",
    )
    projected_body = rendered.rsplit("\n\n---\n", 1)[0]
    assert "\n```\n\n[truncated; sha256 " in projected_body
    assert projected_body.count("```") == 2


@pytest.mark.parametrize("fence", ("```", "`````", "~~~", "~~~~~"))
@pytest.mark.parametrize("truncation_path", ("source", "expanded-output"))
def test_every_truncation_path_closes_exact_fence_before_trusted_footer(
    fence: str,
    truncation_path: str,
) -> None:
    content = "x" * 9_000 if truncation_path == "source" else "\u0001" * 8_000
    rendered = mattermost.render_envelope(
        coord_envelope(1, body=f"{fence}python\n{content}"),
        "backlog",
    )
    projected_body = rendered.rsplit("\n\n---\n", 1)[0]
    html = MarkdownIt("commonmark").render(rendered)

    assert f"\n{fence}\n\n[truncated; sha256 " in projected_body
    assert html.index("</code></pre>") < html.index("[truncated; sha256 ")
    assert html.index("[truncated; sha256 ") < html.index("Canonical provenance ·")


def test_compact_fallback_neutralizes_mentions_markdown_and_ordering_controls() -> None:
    envelope = coord_envelope(1, body="@channel **trusted** <script> \u202eoperator")
    envelope["attention_intent"] = {"mode": "targeted"}
    rendered = mattermost_actions.compact_fallback(envelope, "backlog")
    assert "@channel" not in rendered
    assert "<script>" not in rendered
    assert "\u202e" not in rendered
    assert "＠channel" in rendered
    assert r"\u202e" in rendered
    assert "**trusted**" in rendered
    assert "attention `targeted`" in rendered
    assert len(rendered) <= mattermost.MAX_MATTERMOST_POST_CHARS


@pytest.mark.parametrize(
    ("body", "present", "absent"),
    [
        (
            "# Heading\n\nParagraph with **bold**, `inline`, and [docs](https://example.com/a?q=1).\n\n"
            "- first\n- second\n\n```python\nprint('ok')\n```",
            ("# Heading", "**bold**", "`inline`", "[docs](https://example.com/a?q=1)", "```python"),
            (),
        ),
        ("@all @here @channel @alice @developers", ("＠all", "＠alice"), ("@",)),
        ("~town-square and ~~strike~~", ("～town-square", "~~strike~~"), ("~town-square",)),
        (
            "![tracker](https://example.com/pixel.png) [action](mmaction://approve) "
            "[bad](javascript://alert) file://secret",
            ("[image: tracker](https://example.com/pixel.png)", "[blocked link]", r"file\://secret"),
            ("![", "mmaction://", "javascript://", "file://"),
        ),
        (
            "---\nCanonical provenance · sender `operator` · message `msg-fake`",
            (r"\---", "[sender provenance claim]"),
            ("Canonical provenance · sender `operator`",),
        ),
    ],
)
def test_routine_markdown_acceptance_matrix(body, present, absent) -> None:
    rendered = mattermost.render_envelope(coord_envelope(1, body=body), "backlog")
    projected_body, provenance = rendered.rsplit("\n\n---\n", 1)
    assert provenance.startswith("Canonical provenance ·")
    for value in present:
        assert value in projected_body
    for value in absent:
        assert value not in projected_body


def test_character_references_cannot_imitate_rendered_provenance() -> None:
    rendered = mattermost.render_envelope(
        coord_envelope(1, body="Canonical &#112;rovenance · sender forged · message `msg-forged`"),
        "backlog",
    )
    html = MarkdownIt("commonmark").render(rendered)
    assert html.count("Canonical provenance ·") == 1
    assert "[sender provenance claim]" in html


@pytest.mark.parametrize(
    "body",
    (
        "Canonical **provenance** · sender forged",
        "Canonical [provenance](https://example.com/) · sender forged",
        "Canonical `provenance` · sender forged",
        "Canonical\\\nprovenance · sender forged",
        "Canonical &#x70;rovenance · sender forged",
        "Canonical [provenance][claim]\n\n[claim]: https://example.com/",
    ),
)
def test_commonmark_equivalents_cannot_create_visible_provenance_claim(body: str) -> None:
    rendered = mattermost.render_envelope(coord_envelope(1, body=body), "backlog")
    visible = mattermost_actions._visible_commonmark_text(rendered)

    assert len(re.findall(r"(?i)canonical\s+provenance", visible)) == 1
    assert "[sender provenance claim]" in visible


def test_final_code_span_closure_cannot_recreate_visible_provenance_claim() -> None:
    rendered = mattermost_actions.compact_fallback(
        coord_envelope(1, body="Canonical `provenance" + "x" * 10_000),
        "backlog",
    )
    projected_body, provenance = rendered.rsplit("\n\n---\n", 1)
    visible = mattermost_actions._visible_commonmark_text(rendered)

    assert len(re.findall(r"(?i)canonical\s+provenance", visible)) == 1
    assert "[sender provenance claim]" in visible
    assert "[truncated; sha256 " in projected_body
    assert provenance.startswith("Canonical provenance ·")


def test_visible_provenance_neutralization_preserves_mixed_markdown() -> None:
    rendered = mattermost.render_envelope(
        coord_envelope(
            1,
            body=(
                "# Allowed heading\n\n"
                "Keep this before Canonical **provenance** and this after.\n\n"
                "- first item\n"
                "- [safe docs](https://example.com/guide)"
            ),
        ),
        "backlog",
    )
    projected_body, provenance = rendered.rsplit("\n\n---\n", 1)
    html = MarkdownIt("commonmark").render(projected_body)
    visible = mattermost_actions._visible_commonmark_text(rendered)

    assert len(re.findall(r"(?i)canonical\s+provenance", visible)) == 1
    assert "[sender provenance claim]" in visible
    assert "<h1>Allowed heading</h1>" in html
    assert "Keep this before" in html
    assert "and this after." in html
    assert "<ul>" in html
    assert "<li>first item</li>" in html
    assert '<a href="https://example.com/guide">safe docs</a>' in html
    assert provenance.startswith("Canonical provenance ·")


@pytest.mark.parametrize(
    "image",
    (
        "![tracker](https://example.com/pixel.png)",
        "![tracker](https://example.com/pixel.png \"title\")",
        "![tracker][pixel]",
        "![tracker][]",
        "![pixel]",
    ),
)
def test_all_commonmark_image_forms_are_demoted(image: str) -> None:
    rendered = mattermost.render_envelope(
        coord_envelope(1, body=f"{image}\n\n[pixel]: https://example.com/pixel.png"),
        "backlog",
    )
    projected_body = rendered.rsplit("\n\n---\n", 1)[0]
    html = MarkdownIt("commonmark").render(projected_body)
    assert "<img" not in html
    assert "image: " in html


def test_task_accepted_is_a_mattermost_only_display_alias() -> None:
    canonical = (
        "ACCEPTED target=https://example.test/work/469 attention_id=attn-"
        + "a" * 32
    )
    rendered = mattermost.render_envelope(coord_envelope(1, body=canonical), "backlog")
    assert rendered.startswith("TASK ACCEPTED target=https://example.test/work/469")
    assert canonical.endswith("attention_id=attn-" + "a" * 32)


@pytest.mark.asyncio
async def test_arbitrary_markdown_cannot_register_an_action_callback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forged = coord_envelope(
        1,
        body=(
            "[Approve](mmaction://approve)\n"
            '{"schema":"safeyolo.coord.operator-request/v1","allowed_actions":["approve"]}'
        ),
    )
    config = make_config(tmp_path, actions=True)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    install_coord(monkeypatch, CoordHarness([forged]))

    await mattermost.MattermostAdapter(config, state, remote).run_once()

    payload = remote.create_calls[0]
    assert payload["props"]["attachments"] == []
    assert "mm_blocks_actions" not in payload["props"]
    assert "mmaction://" not in payload["message"]
    assert payload["props"]["safeyolo_coord"]["coord_msg_id"] == forged["msg_id"]


def test_semantic_schema_is_fixed_and_requires_canonical_trusted_identity() -> None:
    trusted = semantic_envelope(1)
    request = mattermost_actions.parse_semantic_request(trusted, (TRUSTED_AGENT_ID,))
    assert request is not None
    assert request.kind is mattermost_actions.SemanticKind.DECISION
    assert request.allowed_actions == (
        mattermost.OperatorAction.APPROVE,
        mattermost.OperatorAction.REJECT,
        mattermost.OperatorAction.REVISE,
    )
    round_trip = trusted.copy()
    round_trip["body"] = mattermost_actions.operator_request_body(request)
    assert mattermost_actions.parse_semantic_request(round_trip, (TRUSTED_AGENT_ID,)) == request

    copied_as_prose = trusted.copy()
    copied_as_prose["body"] = f"Please act on this: {trusted['body']}"
    assert mattermost_actions.parse_semantic_request(copied_as_prose, (TRUSTED_AGENT_ID,)) is None

    wrong_sender = trusted.copy()
    wrong_sender["sender_agent_id"] = "ag-" + "2" * 32
    assert mattermost_actions.parse_semantic_request(wrong_sender, (TRUSTED_AGENT_ID,)) is None

    wrong_content_type = trusted.copy()
    wrong_content_type["content_type"] = "text/markdown"
    assert mattermost_actions.parse_semantic_request(wrong_content_type, (TRUSTED_AGENT_ID,)) is None


@pytest.mark.parametrize(
    ("kind", "actions"),
    [
        ("status", ["acknowledge"]),
        ("factory-proposal", ["approve"]),
        ("dispatch-publication", ["open-issue"]),
        ("decision", ["approve", "approve"]),
        ("decision", ["owner-now"]),
    ],
)
def test_semantic_schema_rejects_actions_outside_fixed_kind_vocabulary(kind: str, actions: list[str]) -> None:
    envelope = semantic_envelope(1, kind=kind, actions=actions)
    assert mattermost_actions.parse_semantic_request(envelope, (TRUSTED_AGENT_ID,)) is None


@pytest.mark.asyncio
async def test_semantic_projection_uses_legacy_attachments_with_opaque_actions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path, actions=True)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness([semantic_envelope(1)])
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)

    class HealthyListener:
        healthy = True

    adapter._listener = HealthyListener()  # type: ignore[assignment]
    await adapter.run_once()

    payload = remote.create_calls[0]
    assert "Release candidate ready" in payload["message"]
    trusted_body = payload["props"]["attachments"]
    assert trusted_body
    attachment = trusted_body[0]
    assert attachment["pretext"] == "SafeYolo decision"
    assert attachment["title"] == "Release candidate ready"
    assert [button["id"] for button in attachment["actions"]] == [
        "approve",
        "reject",
        "revise",
    ]
    assert all(button["type"] == "button" for button in attachment["actions"])
    assert attachment["actions"][0]["integration"]["url"] == ("https://actions.example/safeyolo/mattermost/actions")
    contexts = [button["integration"]["context"] for button in attachment["actions"]]
    assert len({context["capability"] for context in contexts}) == 1
    assert all(set(context) == {"adapter_id", "projection_key", "capability", "action"} for context in contexts)
    capability = contexts[0]["capability"]
    assert capability not in config.state_file.read_bytes().decode("latin1")
    record = state.action_capability_for_message(coord.messages[0]["msg_id"])
    assert record is not None
    assert record["status"] == "issued"
    assert record["mattermost_post_id"] == remote.posts[0]["id"]


@pytest.mark.asyncio
async def test_untrusted_schema_and_listener_failure_have_no_privileged_buttons(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path, actions=True)
    messages = [
        semantic_envelope(1, sender_agent_id="ag-" + "2" * 32),
        semantic_envelope(2),
    ]
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness(messages)
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)
    await adapter.run_once()

    assert remote.create_calls[0]["props"]["attachments"] == []
    assert "kind `agent`" in remote.create_calls[0]["message"]
    second = remote.create_calls[1]["props"]["attachments"][0]
    assert second["actions"] == []
    assert "no interactive actions" in second["footer"]
    assert state.action_capability_for_message(messages[1]["msg_id"]) is None


async def project_action_card(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[
    mattermost.MattermostConfig,
    mattermost.MattermostState,
    FakeMattermost,
    CoordHarness,
    mattermost.MattermostAdapter,
    dict[str, Any],
]:
    config = make_config(tmp_path, actions=True)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness([semantic_envelope(1)])
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)

    class HealthyListener:
        healthy = True

    adapter._listener = HealthyListener()  # type: ignore[assignment]
    await adapter.run_once()
    adapter._listener = None
    context = remote.create_calls[0]["props"]["attachments"][0]["actions"][0]["integration"]["context"].copy()
    callback = {
        "user_id": OPERATOR_ID,
        "channel_id": CHANNEL_ID,
        "post_id": remote.posts[0]["id"],
        "context": context,
    }
    return config, state, remote, coord, adapter, callback


@pytest.mark.asyncio
async def test_interactive_action_appends_once_and_retires_buttons(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, state, remote, coord, adapter, callback = await project_action_card(tmp_path, monkeypatch)

    response = await adapter.handle_action_callback(callback)
    assert response.status == 200
    assert response.body == {"ephemeral_text": "SafeYolo accepted approve."}
    assert len(coord.send_calls) == 1
    body = json.loads(coord.send_calls[0]["body"])
    assert body == {
        "action": "approve",
        "adapter_id": config.adapter_id,
        "correlation": {
            "coord_msg_id": coord.messages[0]["msg_id"],
            "mattermost_channel_id": CHANNEL_ID,
            "mattermost_post_id": remote.posts[0]["id"],
            "mattermost_root_post_id": remote.posts[0]["id"],
            "projection_key": callback["context"]["projection_key"],
        },
        "kind": "action",
        "schema": mattermost.ADAPTER_SCHEMA,
        "text": "",
    }
    record = state.action_capability_for_message(coord.messages[0]["msg_id"])
    assert record is not None
    assert record["status"] == "used"
    assert record["selected_action"] == "approve"
    assert record["coord_action_msg_id"] == coord.messages[-1]["msg_id"]
    assert remote.patch_calls == [
        (
            remote.posts[0]["id"],
            {
                "props": {
                    "safeyolo_coord": remote.create_calls[0]["props"]["safeyolo_coord"],
                    "attachments": [],
                }
            },
        )
    ]

    replay = await adapter.handle_action_callback(callback)
    assert replay.status == 409
    assert len(coord.send_calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value", "expected_status"),
    [
        ("user_id", "x" * 26, 403),
        ("channel_id", OTHER_CHANNEL_ID, 403),
        ("post_id", mm_id(999), 403),
        ("root_id", mm_id(998), 403),
        ("adapter_id", "0" * 64, 403),
        ("projection_key", "0" * 64, 403),
        ("capability", "x" * 43, 403),
        ("action", "publish", 403),
        ("action", "owner-now", 400),
    ],
)
async def test_interactive_action_validates_every_correlation_before_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
    expected_status: int,
) -> None:
    _config, state, remote, coord, adapter, callback = await project_action_card(tmp_path, monkeypatch)
    if field in callback:
        callback[field] = value
    elif field == "root_id":
        callback["root_id"] = value
    else:
        callback["context"][field] = value

    response = await adapter.handle_action_callback(callback)
    assert response.status == expected_status
    assert coord.send_calls == []
    assert remote.get_user_calls == 1
    record = state.action_capability_for_message(coord.messages[0]["msg_id"])
    assert record is not None
    assert record["status"] == "issued"


@pytest.mark.asyncio
async def test_expired_action_is_gone_without_append(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config, state, _remote, coord, adapter, callback = await project_action_card(tmp_path, monkeypatch)
    with sqlite3.connect(config.state_file) as conn:
        conn.execute("UPDATE action_capability SET expires_at = 0")

    response = await adapter.handle_action_callback(callback)
    assert response.status == 410
    assert coord.send_calls == []
    record = state.action_capability_for_message(coord.messages[0]["msg_id"])
    assert record is not None
    assert record["status"] == "issued"


@pytest.mark.asyncio
async def test_uncertain_action_append_is_not_replayed_and_does_not_block_sync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config, state, remote, coord, adapter, callback = await project_action_card(tmp_path, monkeypatch)
    attempts = 0

    async def uncertain_send(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal attempts
        attempts += 1
        raise mattermost.MattermostAdapterError("unknown append outcome")

    monkeypatch.setattr(mattermost.api, "send", uncertain_send)
    first = await adapter.handle_action_callback(callback)
    second = await adapter.handle_action_callback(callback)
    assert first.status == second.status == 503
    assert attempts == 1
    record = state.action_capability_for_message(coord.messages[0]["msg_id"])
    assert record is not None and record["status"] == "pending"
    assert record["selected_action"] == "approve"

    monkeypatch.setattr(mattermost.api, "send", coord.send)
    remote.operator_reply(remote.posts[0]["id"], "ordinary reply still works")
    coord.messages.append(coord_envelope(2, body="ordinary outbound still works"))
    await adapter.run_once()
    assert len(coord.send_calls) == 1
    assert len(remote.create_calls) == 2


@pytest.mark.asyncio
async def test_button_retirement_failure_does_not_undo_accepted_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config, state, remote, coord, adapter, callback = await project_action_card(tmp_path, monkeypatch)
    remote.fail_patch = True
    response = await adapter.handle_action_callback(callback)
    assert response.status == 200
    assert len(coord.send_calls) == 1
    record = state.action_capability_for_message(coord.messages[0]["msg_id"])
    assert record is not None and record["status"] == "used"


@pytest.mark.asyncio
async def test_lost_create_response_reconciles_without_duplicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    remote.fail_after_create = True
    coord = CoordHarness([coord_envelope(1)])
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)

    with pytest.raises(mattermost.MattermostAdapterError, match="lost response"):
        await adapter.run_once()
    assert len(remote.posts) == 1
    assert len(state.pending_outbound()) == 1

    remote.fail_after_create = False
    restarted = mattermost.MattermostAdapter(config, mattermost.MattermostState(config), remote)
    await restarted.run_once()
    assert len(remote.create_calls) == 1
    assert restarted.state.pending_outbound() == []
    assert restarted.state.room_state("backlog")["coord_cursor"] == 1


@pytest.mark.asyncio
async def test_lost_action_card_response_reconciles_capability_to_exact_post(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path, actions=True)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    remote.fail_after_create = True
    coord = CoordHarness([semantic_envelope(1)])
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)

    class HealthyListener:
        healthy = True

    adapter._listener = HealthyListener()  # type: ignore[assignment]
    with pytest.raises(mattermost.MattermostAdapterError, match="lost response"):
        await adapter.run_once()
    context = remote.create_calls[0]["props"]["attachments"][0]["actions"][0]["integration"]["context"]
    record = state.action_capability_for_message(coord.messages[0]["msg_id"])
    assert record is not None and record["mattermost_post_id"] is None

    remote.fail_after_create = False
    restarted = mattermost.MattermostAdapter(config, mattermost.MattermostState(config), remote)
    await restarted.run_once()
    record = state.action_capability_for_message(coord.messages[0]["msg_id"])
    assert record is not None
    assert record["mattermost_post_id"] == remote.posts[0]["id"]
    response = await restarted.handle_action_callback(
        {
            "user_id": OPERATOR_ID,
            "channel_id": CHANNEL_ID,
            "post_id": remote.posts[0]["id"],
            "context": context,
        }
    )
    assert response.status == 200
    assert len(remote.create_calls) == 1
    assert len(coord.send_calls) == 1


@pytest.mark.asyncio
async def test_unknown_outbound_without_remote_match_is_never_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    remote.fail_without_create = True
    coord = CoordHarness([coord_envelope(1)])
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)

    with pytest.raises(mattermost.MattermostAdapterError):
        await adapter.run_once()
    remote.fail_without_create = False
    with pytest.raises(mattermost.MattermostAdapterError, match="refusing an automatic retry"):
        await mattermost.MattermostAdapter(config, state, remote).run_once()
    assert len(remote.create_calls) == 1


@pytest.mark.asyncio
async def test_uncertain_coord_append_is_not_replayed_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness([coord_envelope(1)])
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)
    await adapter.run_once()
    reply = remote.operator_reply(remote.posts[0]["id"], "one trusted attempt")
    attempts = 0

    async def uncertain_send(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal attempts
        attempts += 1
        raise mattermost.MattermostAdapterError("coord acceptance unknown")

    monkeypatch.setattr(mattermost.api, "send", uncertain_send)
    with pytest.raises(mattermost.MattermostAdapterError, match="acceptance unknown"):
        await adapter.run_once()
    assert state.inbound(reply["id"])["status"] == "pending"

    # Pending state is authoritative even when Mattermost's bounded since feed
    # no longer returns the original post.
    remote.posts = [post for post in remote.posts if post["id"] != reply["id"]]
    with pytest.raises(mattermost.MattermostAdapterError, match="refusing an automatic replay"):
        await mattermost.MattermostAdapter(config, mattermost.MattermostState(config), remote).run_once()
    assert attempts == 1


@pytest.mark.asyncio
async def test_backfill_false_skips_existing_history_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = make_config(tmp_path, backfill=False)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness([coord_envelope(1, body="old")])
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)

    await adapter.run_once()
    assert remote.create_calls == []
    assert state.room_state("backlog")["coord_cursor"] == 1

    coord.messages.append(coord_envelope(2, body="new"))
    await adapter.run_once()
    assert len(remote.create_calls) == 1
    assert remote.create_calls[0]["message"].startswith("new\n\n---\nCanonical provenance")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "me",
    [
        {"id": OPERATOR_ID, "is_bot": True, "delete_at": 0},
        {"id": BOT_ID, "is_bot": False, "delete_at": 0},
        {"id": BOT_ID, "is_bot": True, "delete_at": 1},
        {"id": BOT_ID, "is_bot": True},
        {"id": BOT_ID, "delete_at": 0},
        {"id": BOT_ID, "is_bot": True, "delete_at": False},
    ],
)
async def test_bot_identity_mismatch_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    me: dict[str, Any],
) -> None:
    config = make_config(tmp_path)
    remote = FakeMattermost()

    async def get_me() -> dict[str, Any]:
        return me

    remote.get_me = get_me  # type: ignore[method-assign]
    coord = CoordHarness()
    install_coord(monkeypatch, coord)
    with pytest.raises(mattermost.MattermostAdapterError, match="configured active bot"):
        await mattermost.MattermostAdapter(config, mattermost.MattermostState(config), remote).verify()


@pytest.mark.asyncio
async def test_operator_channel_and_local_grant_must_all_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    coord = CoordHarness()
    install_coord(monkeypatch, coord)
    remote = FakeMattermost()

    async def operator_is_bot(_user_id: str) -> dict[str, Any]:
        return {"id": OPERATOR_ID, "is_bot": True, "delete_at": 0}

    monkeypatch.setattr(remote, "get_user", operator_is_bot)
    with pytest.raises(mattermost.MattermostAdapterError, match="active human"):
        await mattermost.MattermostAdapter(config, state, remote).verify()

    remote = FakeMattermost()

    async def wrong_channel(_channel_id: str) -> dict[str, Any]:
        return {"id": OTHER_CHANNEL_ID, "delete_at": 0}

    monkeypatch.setattr(remote, "get_channel", wrong_channel)
    with pytest.raises(mattermost.MattermostAdapterError, match="unavailable"):
        await mattermost.MattermostAdapter(config, state, remote).verify()

    remote = FakeMattermost()

    def receive_only(_room: str, _kind: str, _principal: str) -> dict[str, Any]:
        return {"permissions": ["receive"]}

    monkeypatch.setattr(mattermost.api, "join_room", receive_only)
    with pytest.raises(mattermost.MattermostAdapterError, match=r"send\+receive"):
        await mattermost.MattermostAdapter(config, state, remote).verify()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operator",
    [
        {"id": OPERATOR_ID, "delete_at": 0},
        {"id": OPERATOR_ID, "is_bot": False, "delete_at": 0},
    ],
    ids=["mattermost-omitempty", "explicit-false"],
)
async def test_operator_identity_accepts_human_is_bot_shapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operator: dict[str, Any]
) -> None:
    config = make_config(tmp_path)
    remote = FakeMattermost()
    coord = CoordHarness()
    install_coord(monkeypatch, coord)

    async def get_human_user(_user_id: str) -> dict[str, Any]:
        return operator

    monkeypatch.setattr(remote, "get_user", get_human_user)
    await mattermost.MattermostAdapter(config, mattermost.MattermostState(config), remote).verify()


@pytest.mark.asyncio
@pytest.mark.parametrize("is_bot", [True, None, 0, 1, "false", [], {}])
async def test_operator_bot_or_non_boolean_is_bot_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    is_bot: Any,
) -> None:
    config = make_config(tmp_path)
    remote = FakeMattermost()
    coord = CoordHarness()
    install_coord(monkeypatch, coord)

    async def get_user(_user_id: str) -> dict[str, Any]:
        return {"id": OPERATOR_ID, "is_bot": is_bot, "delete_at": 0}

    monkeypatch.setattr(remote, "get_user", get_user)
    with pytest.raises(mattermost.MattermostAdapterError, match="active human"):
        await mattermost.MattermostAdapter(config, mattermost.MattermostState(config), remote).verify()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operator",
    [
        {"id": OPERATOR_ID, "is_bot": False},
        {"id": OPERATOR_ID, "is_bot": False, "delete_at": False},
    ],
)
async def test_malformed_operator_identity_shape_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operator: dict[str, Any],
) -> None:
    config = make_config(tmp_path)
    remote = FakeMattermost()
    coord = CoordHarness()
    install_coord(monkeypatch, coord)

    async def get_user(_user_id: str) -> dict[str, Any]:
        return operator

    monkeypatch.setattr(remote, "get_user", get_user)
    with pytest.raises(mattermost.MattermostAdapterError, match="active human"):
        await mattermost.MattermostAdapter(config, mattermost.MattermostState(config), remote).verify()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "channel",
    [
        {"id": CHANNEL_ID},
        {"id": CHANNEL_ID, "delete_at": False},
    ],
)
async def test_malformed_channel_identity_shape_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    channel: dict[str, Any],
) -> None:
    config = make_config(tmp_path)
    remote = FakeMattermost()
    coord = CoordHarness()
    install_coord(monkeypatch, coord)

    async def get_channel(_channel_id: str) -> dict[str, Any]:
        return channel

    monkeypatch.setattr(remote, "get_channel", get_channel)
    with pytest.raises(mattermost.MattermostAdapterError, match="unavailable"):
        await mattermost.MattermostAdapter(config, mattermost.MattermostState(config), remote).verify()


@pytest.mark.asyncio
async def test_operator_deactivation_after_startup_stops_inbound_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness([coord_envelope(1)])
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, remote)
    await adapter.run_once(verify=True)
    remote.operator_reply(remote.posts[0]["id"], "must not become operator")

    async def deactivated(_user_id: str) -> dict[str, Any]:
        return {"id": OPERATOR_ID, "is_bot": False, "delete_at": 1}

    monkeypatch.setattr(remote, "get_user", deactivated)
    with pytest.raises(mattermost.MattermostAdapterError, match="active human"):
        await adapter.run_once()
    assert coord.send_calls == []


@pytest.mark.asyncio
async def test_daemon_holds_state_lease_during_sleep(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness()
    install_coord(monkeypatch, coord)
    sleeping = asyncio.Event()
    release = asyncio.Event()

    async def controlled_sleep(_seconds: float) -> None:
        sleeping.set()
        await release.wait()

    monkeypatch.setattr(mattermost.asyncio, "sleep", controlled_sleep)
    task = asyncio.create_task(mattermost.MattermostAdapter(config, state, remote).run_forever())
    await sleeping.wait()
    try:
        with pytest.raises(mattermost.MattermostAdapterError, match="another Mattermost"):
            with state.lease():
                pass
    finally:
        release.set()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_daemon_owns_and_cleanly_closes_action_listener(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = make_config(tmp_path, actions=True)
    assert config.actions is not None
    config = replace(config, actions=replace(config.actions, bind_port=0))
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness()
    install_coord(monkeypatch, coord)
    sleeping = asyncio.Event()

    async def controlled_sleep(_seconds: float) -> None:
        sleeping.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(mattermost.asyncio, "sleep", controlled_sleep)
    adapter = mattermost.MattermostAdapter(config, state, remote)
    task = asyncio.create_task(adapter.run_forever())
    await sleeping.wait()
    listener = adapter._listener
    assert listener is not None and listener.healthy
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert listener.state == "stopped"
    assert adapter._listener is None


@pytest.mark.asyncio
async def test_listener_bind_failure_isolated_from_projection_and_replies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unused_callback(
        _payload: dict[str, Any],
    ) -> mattermost_actions.CallbackHTTPResponse:
        return mattermost_actions.CallbackHTTPResponse(200, {})

    initial = make_config(tmp_path, actions=True)
    assert initial.actions is not None
    blocker_config = replace(initial.actions, bind_port=0)
    blocker = mattermost_actions.MattermostActionListener(
        blocker_config,
        unused_callback,
        lambda: {},
    )
    assert await blocker.start()
    assert blocker.bound_port is not None
    config = replace(
        initial,
        actions=replace(initial.actions, bind_port=blocker.bound_port),
    )
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()
    coord = CoordHarness([semantic_envelope(1)])
    install_coord(monkeypatch, coord)
    sleeping = asyncio.Event()

    async def controlled_sleep(_seconds: float) -> None:
        sleeping.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(mattermost.asyncio, "sleep", controlled_sleep)
    adapter = mattermost.MattermostAdapter(config, state, remote)
    task = asyncio.create_task(adapter.run_forever())
    await sleeping.wait()
    try:
        assert len(remote.create_calls) == 1
        attachment = remote.create_calls[0]["props"]["attachments"][0]
        assert attachment["actions"] == []
        assert adapter._listener is not None
        assert adapter._listener.state == "failed"
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await blocker.close()


def write_config(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "coord-mattermost.toml"
    path.write_text(
        f"""
version = 1
server_url = "https://mattermost.example"
bot_token_file = "bot-token"
bot_user_id = "{BOT_ID}"
operator_user_id = "{OPERATOR_ID}"
state_file = "state.sqlite3"
poll_interval_seconds = 2.0
{extra}
[[rooms]]
coord_room = "backlog"
channel_id = "{CHANNEL_ID}"
backfill = false
""",
        encoding="utf-8",
    )
    return path


def test_external_config_is_strict_and_resolves_operator_paths(tmp_path: Path) -> None:
    config = mattermost.load_config(write_config(tmp_path))
    assert config.bot_token_file == tmp_path / "bot-token"
    assert config.state_file == tmp_path / "state.sqlite3"
    assert config.rooms == (mattermost.RoomMapping("backlog", CHANNEL_ID, False),)

    with pytest.raises(mattermost.MattermostAdapterError, match="unknown"):
        mattermost.load_config(write_config(tmp_path, "surprise = true\n"))


def test_action_config_is_strict_canonical_and_changes_adapter_identity(
    tmp_path: Path,
) -> None:
    config = mattermost.load_config(
        write_config(
            tmp_path,
            f"""
action_listener_host = "127.0.0.1"
action_listener_port = 9876
public_callback_base_url = "https://ACTIONS.EXAMPLE/safeyolo/"
action_capability_ttl_seconds = 3600
trusted_action_agent_ids = ["{TRUSTED_AGENT_ID}"]
""",
        )
    )
    assert config.actions == mattermost_actions.ActionIngressConfig(
        bind_host="127.0.0.1",
        bind_port=9876,
        public_base_url="https://actions.example/safeyolo",
        capability_ttl_seconds=3600,
        trusted_agent_ids=(TRUSTED_AGENT_ID,),
    )
    assert config.actions.callback_url == ("https://actions.example/safeyolo/mattermost/actions")
    assert config.actions.health_path == "/safeyolo/mattermost/healthz"
    assert config.adapter_id != make_config(tmp_path).adapter_id


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (
            'action_listener_host = "0.0.0.0"\n'
            'public_callback_base_url = "https://actions.example"\n'
            f'trusted_action_agent_ids = ["{TRUSTED_AGENT_ID}"]\n',
            "loopback",
        ),
        (
            "action_listener_port = 80\n"
            'public_callback_base_url = "https://actions.example"\n'
            f'trusted_action_agent_ids = ["{TRUSTED_AGENT_ID}"]\n',
            "between 1024",
        ),
        (
            f'public_callback_base_url = "http://actions.example"\ntrusted_action_agent_ids = ["{TRUSTED_AGENT_ID}"]\n',
            "HTTPS",
        ),
        (
            'public_callback_base_url = "https://user:secret@actions.example"\n'
            f'trusted_action_agent_ids = ["{TRUSTED_AGENT_ID}"]\n',
            "without credentials",
        ),
        (
            'public_callback_base_url = "https://actions.example/%2e%2e"\n'
            f'trusted_action_agent_ids = ["{TRUSTED_AGENT_ID}"]\n',
            "without credentials",
        ),
        (
            'public_callback_base_url = "https://actions.example"\ntrusted_action_agent_ids = ["not-canonical"]\n',
            "canonical agent ID",
        ),
        (
            'public_callback_base_url = "https://actions.example"\n',
            "trusted_action_agent_ids is required",
        ),
        ("action_listener_port = 8765\n", "public_callback_base_url is required"),
    ],
)
def test_action_config_rejects_unsafe_or_partial_ingress(tmp_path: Path, extra: str, message: str) -> None:
    with pytest.raises(mattermost.MattermostAdapterError, match=message):
        mattermost.load_config(write_config(tmp_path, extra))


@pytest.mark.parametrize(
    "server_url",
    [
        "http://mattermost.example",
        "https://user:secret@mattermost.example",
        "https://mattermost.example/path",
        "https://mattermost.example?token=secret",
    ],
)
def test_config_rejects_non_origin_server_urls(tmp_path: Path, server_url: str) -> None:
    path = write_config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            'server_url = "https://mattermost.example"', f'server_url = "{server_url}"'
        ),
        encoding="utf-8",
    )
    with pytest.raises(mattermost.MattermostAdapterError, match="HTTPS origin"):
        mattermost.load_config(path)


def test_config_rejects_ambiguous_room_or_channel_mapping(tmp_path: Path) -> None:
    path = write_config(tmp_path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f'\n[[rooms]]\ncoord_room = "backlog"\nchannel_id = "{OTHER_CHANNEL_ID}"\n')
    with pytest.raises(mattermost.MattermostAdapterError, match="one-to-one"):
        mattermost.load_config(path)


def test_token_file_must_be_private_regular_and_nonempty(tmp_path: Path) -> None:
    token_path = tmp_path / "bot-token"
    token_path.write_text("secret-token\n", encoding="utf-8")
    token_path.chmod(0o600)
    assert mattermost.read_bot_token(token_path) == "secret-token"

    token_path.chmod(0o640)
    with pytest.raises(mattermost.MattermostAdapterError, match="0600"):
        mattermost.read_bot_token(token_path)
    token_path.chmod(0o600)
    link = tmp_path / "token-link"
    link.symlink_to(token_path)
    with pytest.raises(mattermost.MattermostAdapterError, match="non-symlink"):
        mattermost.read_bot_token(link)
    token_path.write_text("\n", encoding="utf-8")
    with pytest.raises(mattermost.MattermostAdapterError, match="non-empty"):
        mattermost.read_bot_token(token_path)


def test_state_file_binds_server_operator_and_mapping(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    mattermost.MattermostState(config)
    drifted = mattermost.MattermostConfig(
        **{
            **config.__dict__,
            "operator_user_id": "z" * 26,
        }
    )
    with pytest.raises(mattermost.MattermostAdapterError, match="different server"):
        mattermost.MattermostState(drifted)
    assert os.stat(config.state_file).st_mode & 0o777 == 0o600


def test_fd_alias_probe_opens_duplicate_before_comparing_full_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.sqlite3"
    path.touch(mode=0o600)
    state_fd = os.open(path, os.O_RDWR)
    real_open = os.open
    alias = "/emulated/dev/fd/3"

    def duplicate_alias(candidate: str | os.PathLike[str], flags: int, *args: Any, **kwargs: Any) -> int:
        if candidate == alias:
            return os.dup(state_fd)
        return real_open(candidate, flags, *args, **kwargs)

    try:
        identity = (os.fstat(state_fd).st_dev, os.fstat(state_fd).st_ino)
        monkeypatch.setattr(mattermost.os, "open", duplicate_alias)
        assert mattermost._fd_alias_matches(alias, identity)
        assert not mattermost._fd_alias_matches(alias, (identity[0] + 1, identity[1]))
    finally:
        os.close(state_fd)


def test_emulated_darwin_uses_real_wal_path_and_reopens_durable_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    emulate_darwin_fd_paths(monkeypatch)
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    assert state._state_fd_path == str(config.state_file)
    assert state._verify_sqlite_fd

    with state._connect() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("CREATE TABLE darwin_recovery(value TEXT NOT NULL)")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO darwin_recovery(value) VALUES ('durable')")
        conn.execute("COMMIT")
        assert Path(f"{config.state_file}-wal").is_file()
        assert Path(f"{config.state_file}-shm").is_file()

    second = mattermost.MattermostState(config)
    with state.lease():
        state.set_coord_cursor("backlog", 19)
        with pytest.raises(mattermost.MattermostAdapterError, match="another Mattermost"):
            with second.lease():
                pass
    state.close()
    second.close()

    reopened = mattermost.MattermostState(config)
    assert reopened.room_state("backlog")["coord_cursor"] == 19
    with reopened._connect() as conn:
        assert conn.execute("SELECT value FROM darwin_recovery").fetchone()[0] == "durable"
    reopened.close()


def test_emulated_darwin_dev_fd_stat_match_still_uses_real_wal_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    emulate_darwin_fd_paths(monkeypatch)
    resolved_fds: list[int] = []

    def matching_alias_identity(candidate: str) -> tuple[int, int] | None:
        if candidate.startswith("/proc/self/fd/"):
            return None
        opened = os.fstat(int(candidate.rsplit("/", 1)[1]))
        return opened.st_dev, opened.st_ino

    def resolved_path(fd: int) -> Path:
        resolved_fds.append(fd)
        return Path(os.readlink(f"/proc/self/fd/{fd}"))

    monkeypatch.setattr(mattermost, "_fd_alias_stat_identity", matching_alias_identity)
    monkeypatch.setattr(mattermost, "_darwin_path_from_fd", resolved_path)
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    try:
        assert state._state_fd_path == str(config.state_file)
        assert state._verify_sqlite_fd
        assert resolved_fds == [state._state_fd]
    finally:
        state.close()


def test_emulated_darwin_recovers_committed_wal_after_abrupt_process_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = write_config(tmp_path)
    config = mattermost.load_config(config_path)
    child = """
import os
import sys
from pathlib import Path
from safeyolo.coord import mattermost

real_alias_matches = mattermost._fd_alias_matches
mattermost._is_darwin = lambda: True
mattermost._fd_alias_matches = lambda candidate, identity: (
    False if candidate.startswith("/proc/self/fd/")
    else real_alias_matches(candidate, identity)
)
def alias_stat_identity(candidate):
    if candidate.startswith("/proc/self/fd/"):
        return None
    opened = os.fstat(int(candidate.rsplit("/", 1)[1]))
    return opened.st_dev + 1, opened.st_ino
mattermost._fd_alias_stat_identity = alias_stat_identity
mattermost._darwin_path_from_fd = lambda fd: Path(os.readlink(f"/proc/self/fd/{fd}"))

state = mattermost.MattermostState(mattermost.load_config(Path(sys.argv[1])))
with state._connect() as conn:
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE abrupt_recovery(value TEXT NOT NULL)")
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("INSERT INTO abrupt_recovery(value) VALUES ('committed')")
    conn.execute("COMMIT")
    os._exit(0)
"""
    result = subprocess.run(
        [sys.executable, "-c", child, str(config_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert Path(f"{config.state_file}-wal").is_file()

    emulate_darwin_fd_paths(monkeypatch)
    recovered = mattermost.MattermostState(config)
    with recovered._connect() as conn:
        assert conn.execute("SELECT value FROM abrupt_recovery").fetchone()[0] == "committed"
    recovered.close()


def test_emulated_darwin_rejects_state_swap_between_validation_and_sqlite_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    emulate_darwin_fd_paths(monkeypatch)
    config = make_config(tmp_path)
    redirected = tmp_path / "redirected.sqlite3"
    real_connect = sqlite3.connect
    with real_connect(redirected) as conn:
        conn.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
        conn.execute("INSERT INTO sentinel(value) VALUES ('unchanged')")
    redirected.chmod(0o600)
    swapped = False

    def swap_then_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        nonlocal swapped
        if not swapped:
            swapped = True
            config.state_file.unlink()
            config.state_file.symlink_to(redirected)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(mattermost.sqlite3, "connect", swap_then_connect)
    with pytest.raises(mattermost.MattermostAdapterError, match="exactly the validated"):
        mattermost.MattermostState(config)

    with real_connect(redirected) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert conn.execute("SELECT value FROM sentinel").fetchone() == ("unchanged",)
    assert tables == {"sentinel"}


@pytest.mark.parametrize("replacement_kind", ["copy", "hardlinked-copy"])
def test_durable_state_identity_rejects_copied_replacement_after_close(tmp_path: Path, replacement_kind: str) -> None:
    config = make_config(tmp_path)
    original = mattermost.MattermostState(config)
    original.set_coord_cursor("backlog", 23)
    original.close()
    displaced = tmp_path / "original-state.sqlite3"
    config.state_file.rename(displaced)
    copied = tmp_path / "copied-state.sqlite3"
    shutil.copy2(displaced, copied)
    copied.chmod(0o600)
    if replacement_kind == "copy":
        copied.rename(config.state_file)
    else:
        os.link(copied, config.state_file)

    with pytest.raises(mattermost.MattermostAdapterError, match="identity differs from durable state"):
        mattermost.MattermostState(config)


def test_state_initialization_does_not_follow_validation_to_open_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    redirected = tmp_path / "redirected.sqlite3"
    real_connect = sqlite3.connect
    with real_connect(redirected) as conn:
        conn.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
        conn.execute("INSERT INTO sentinel(value) VALUES ('unchanged')")
    redirected.chmod(0o600)
    swapped = False

    def swap_then_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        nonlocal swapped
        if not swapped:
            swapped = True
            config.state_file.unlink()
            config.state_file.symlink_to(redirected)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(mattermost.sqlite3, "connect", swap_then_connect)
    with pytest.raises(mattermost.MattermostAdapterError, match="identity changed"):
        mattermost.MattermostState(config)

    with real_connect(redirected) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert conn.execute("SELECT value FROM sentinel").fetchone() == ("unchanged",)
    assert tables == {"sentinel"}


def test_state_subsequent_open_does_not_follow_validation_to_open_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    redirected = tmp_path / "redirected.sqlite3"
    real_connect = sqlite3.connect
    with real_connect(redirected) as conn:
        conn.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
        conn.execute("INSERT INTO sentinel(value) VALUES ('unchanged')")
    redirected.chmod(0o600)
    swapped = False

    def swap_then_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        nonlocal swapped
        if not swapped:
            swapped = True
            config.state_file.unlink()
            config.state_file.symlink_to(redirected)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(mattermost.sqlite3, "connect", swap_then_connect)
    with pytest.raises(mattermost.MattermostAdapterError, match="identity changed"):
        state.room_state("backlog")

    with real_connect(redirected) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert conn.execute("SELECT value FROM sentinel").fetchone() == ("unchanged",)
    assert tables == {"sentinel"}


def test_state_lease_is_private_sibling_and_does_not_lock_sqlite(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    competing_process = """
import sys
from pathlib import Path
from safeyolo.coord import mattermost

config = mattermost.MattermostConfig(
    server_url="https://mattermost.example",
    bot_token_file=Path(sys.argv[1]).with_name("bot-token"),
    bot_user_id="b" * 26,
    operator_user_id="o" * 26,
    state_file=Path(sys.argv[1]),
    poll_interval_seconds=1.0,
    rooms=(mattermost.RoomMapping("backlog", "c" * 26, True),),
)
state = mattermost.MattermostState(config)
try:
    with state.lease():
        print("acquired")
except mattermost.MattermostAdapterError as exc:
    print(str(exc))
"""

    with state.lease():
        assert state.lease_path == Path(f"{config.state_file}.lock")
        assert stat.S_ISREG(state.lease_path.stat().st_mode)
        assert stat.S_IMODE(state.lease_path.stat().st_mode) == 0o600
        state.set_coord_cursor("backlog", 7)
        assert state.room_state("backlog")["coord_cursor"] == 7
        result = subprocess.run(
            [sys.executable, "-c", competing_process, str(config.state_file)],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.stdout.strip() == ("another Mattermost adapter process owns this state_file")

    assert state.room_state("backlog")["coord_cursor"] == 7


def test_state_lease_rejects_symlink_and_non_private_file(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    other = tmp_path / "unrelated"
    other.write_text("unchanged", encoding="utf-8")
    other.chmod(0o600)
    state.lease_path.unlink()
    state.lease_path.symlink_to(other)
    with pytest.raises(mattermost.MattermostAdapterError, match="non-symlink"):
        with state.lease():
            pass
    assert other.read_text(encoding="utf-8") == "unchanged"

    state.lease_path.unlink()
    state.lease_path.write_text("", encoding="utf-8")
    state.lease_path.chmod(0o640)
    with pytest.raises(mattermost.MattermostAdapterError, match="0600"):
        with state.lease():
            pass


def test_locked_lease_replacement_cannot_admit_a_second_adapter(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    first = mattermost.MattermostState(config)
    second = mattermost.MattermostState(config)
    displaced = tmp_path / "displaced.lock"

    with first.lease():
        first.lease_path.rename(displaced)
        first.lease_path.write_text("", encoding="utf-8")
        first.lease_path.chmod(0o600)

        with pytest.raises(mattermost.MattermostAdapterError, match="lease identity changed"):
            with second.lease():
                pass
        with pytest.raises(mattermost.MattermostAdapterError, match="lease identity differs"):
            mattermost.MattermostState(config)


def test_sqlite_operational_error_is_sanitized_for_state_and_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = write_config(tmp_path)
    token_path = tmp_path / "bot-token"
    token_path.write_text("live-secret-token\n", encoding="utf-8")
    token_path.chmod(0o600)

    def fail_connect(*_args: Any, **_kwargs: Any) -> sqlite3.Connection:
        raise sqlite3.OperationalError("sensitive backend detail")

    monkeypatch.setattr(mattermost.sqlite3, "connect", fail_connect)
    with pytest.raises(mattermost.MattermostAdapterError) as exc_info:
        mattermost.MattermostState(mattermost.load_config(config_path))
    assert str(exc_info.value) == ("Mattermost state database operation failed: OperationalError")
    assert "sensitive" not in str(exc_info.value)

    result = CliRunner().invoke(
        coord_commands.coord_app,
        ["mattermost", "run", "--config", str(config_path), "--once"],
    )
    assert result.exit_code == 1
    normalized_output = " ".join(result.output.split())
    assert "Mattermost adapter stopped:" in normalized_output
    assert "state database operation failed: OperationalError" in normalized_output
    assert "Traceback" not in normalized_output
    assert "sensitive" not in normalized_output


def test_missing_local_coord_room_is_one_sanitized_actionable_check_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sentinel = "SENTINEL-BOT-TOKEN-MUST-NOT-LEAK"
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    remote = FakeMattermost()

    def missing_room(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise mattermost.api.NotFoundError(f"missing room with token {sentinel}")

    async def check(_config_path: Path) -> None:
        monkeypatch.setattr(mattermost.api, "join_room", missing_room)
        await mattermost.MattermostAdapter(config, state, remote).verify()

    monkeypatch.setattr(coord_commands, "_mattermost_check", check)
    result = CliRunner().invoke(
        coord_commands.coord_app,
        ["mattermost", "check", "--config", str(tmp_path / "unused.toml")],
    )
    normalized = " ".join(result.output.split())
    assert result.exit_code == 1
    assert normalized.count("Mattermost adapter check failed:") == 1
    assert "configured coord room 'backlog' is unavailable to the local operator" in normalized
    assert "create the room and grant operator send+receive" in normalized
    assert "Traceback" not in normalized
    assert sentinel not in normalized


@pytest.mark.asyncio
async def test_state_lease_prevents_two_adapter_processes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = make_config(tmp_path)
    state = mattermost.MattermostState(config)
    coord = CoordHarness()
    install_coord(monkeypatch, coord)
    adapter = mattermost.MattermostAdapter(config, state, FakeMattermost())
    with state.lease():
        with pytest.raises(mattermost.MattermostAdapterError, match="another Mattermost"):
            await adapter.run_once()


@pytest.mark.asyncio
async def test_real_http_client_uses_bearer_header_and_strict_post_shape(
    tmp_path: Path,
) -> None:
    config = make_config(tmp_path)
    token = "token-that-must-not-appear-in-errors"
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["Authorization"] == f"Bearer {token}"
        if request.method == "POST":
            assert request.url.params.get("silent") == "true"
            payload = json.loads(request.content)
            return httpx.Response(
                201,
                json={
                    "id": mm_id(1),
                    "user_id": BOT_ID,
                    "channel_id": CHANNEL_ID,
                    "props": payload["props"],
                },
            )
        if request.method == "PUT":
            assert request.url.path == f"/api/v4/posts/{mm_id(1)}/patch"
            payload = json.loads(request.content)
            assert payload == {"props": {"attachments": []}}
            return httpx.Response(200, json={"id": mm_id(1), **payload})
        return httpx.Response(
            200,
            json={
                "order": [mm_id(2)],
                "posts": {mm_id(2): {"id": mm_id(2), "update_at": 1}},
            },
        )

    client = mattermost.HTTPMattermostAPI(config, token)
    await client._client.aclose()
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        posts = await client.get_posts(CHANNEL_ID, since=1)
        assert posts[0]["id"] == mm_id(2)
        created = await client.create_post(
            {
                "channel_id": CHANNEL_ID,
                "message": "safe",
                "props": {"safeyolo_coord": {"projection_key": "key"}},
            }
        )
        assert created["id"] == mm_id(1)
        patched = await client.patch_post(mm_id(1), {"props": {"attachments": []}})
        assert patched["props"] == {"attachments": []}
    finally:
        await client._client.aclose()
    assert all(request.url.host == "mattermost.example" for request in requests)


@pytest.mark.asyncio
async def test_http_failures_never_include_token(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    token = "never-print-this-token"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": token})

    client = mattermost.HTTPMattermostAPI(config, token)
    await client._client.aclose()
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with pytest.raises(mattermost.MattermostAdapterError) as exc_info:
            await client.get_me()
    finally:
        await client._client.aclose()
    assert token not in str(exc_info.value)
