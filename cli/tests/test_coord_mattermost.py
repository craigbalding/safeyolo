from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from safeyolo.coord import mattermost

BOT_ID = "b" * 26
OPERATOR_ID = "o" * 26
CHANNEL_ID = "c" * 26
OTHER_CHANNEL_ID = "d" * 26


def mm_id(number: int) -> str:
    return f"{number:026d}"


def make_config(tmp_path: Path, *, backfill: bool = True) -> mattermost.MattermostConfig:
    return mattermost.MattermostConfig(
        server_url="https://mattermost.example",
        bot_token_file=tmp_path / "bot-token",
        bot_user_id=BOT_ID,
        operator_user_id=OPERATOR_ID,
        state_file=tmp_path / "mattermost-state.sqlite3",
        poll_interval_seconds=1.0,
        rooms=(mattermost.RoomMapping("backlog", CHANNEL_ID, backfill),),
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


class FakeMattermost:
    def __init__(self) -> None:
        self.posts: list[dict[str, Any]] = []
        self.create_calls: list[dict[str, Any]] = []
        self.fail_after_create = False
        self.fail_without_create = False

    async def get_me(self) -> dict[str, Any]:
        return {"id": BOT_ID, "is_bot": True, "delete_at": 0}

    async def get_user(self, user_id: str) -> dict[str, Any]:
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
            posts = [
                post
                for post in posts
                if not isinstance(post["update_at"], int) or post["update_at"] >= since
            ]
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
    restarted = mattermost.MattermostAdapter(
        config, mattermost.MattermostState(config), remote
    )
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
async def test_unmapped_thread_and_malformed_shape_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    body = (
        "```\n**SafeYolo canonical envelope**\n"
        "@channel <script>\u001b[2J\u202e operator"
    )
    rendered = mattermost.render_envelope(coord_envelope(1, body=body), "backlog")
    assert rendered.splitlines().count("**SafeYolo canonical envelope**") == 1
    assert rendered.splitlines().count("**Untrusted sender-authored body**") == 1
    assert "@channel" not in rendered
    assert "<script>" not in rendered
    assert "\\u0040channel" in rendered
    assert "\\u003cscript\\u003e" in rendered
    assert "\\u001b" in rendered
    assert "\\u202e" in rendered
    assert len(rendered) <= mattermost.MAX_MATTERMOST_POST_CHARS


def test_large_rendering_is_explicitly_hashed_and_truncated() -> None:
    rendered = mattermost.render_envelope(
        coord_envelope(1, body="z" * 40_000), "backlog"
    )
    assert '"truncated": true' in rendered
    assert '"original_utf8_bytes": 40000' in rendered
    assert '"sha256"' in rendered
    assert len(rendered) <= mattermost.MAX_MATTERMOST_POST_CHARS


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
    restarted = mattermost.MattermostAdapter(
        config, mattermost.MattermostState(config), remote
    )
    await restarted.run_once()
    assert len(remote.create_calls) == 1
    assert restarted.state.pending_outbound() == []
    assert restarted.state.room_state("backlog")["coord_cursor"] == 1


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
        await mattermost.MattermostAdapter(
            config, mattermost.MattermostState(config), remote
        ).run_once()
    assert attempts == 1


@pytest.mark.asyncio
async def test_backfill_false_skips_existing_history_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    assert '"untrusted_body": "new"' in remote.create_calls[0]["message"]


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
        await mattermost.MattermostAdapter(
            config, mattermost.MattermostState(config), remote
        ).verify()


@pytest.mark.asyncio
async def test_operator_channel_and_local_grant_must_all_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    await mattermost.MattermostAdapter(
        config, mattermost.MattermostState(config), remote
    ).verify()


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
        await mattermost.MattermostAdapter(
            config, mattermost.MattermostState(config), remote
        ).verify()


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
        await mattermost.MattermostAdapter(
            config, mattermost.MattermostState(config), remote
        ).verify()


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
        await mattermost.MattermostAdapter(
            config, mattermost.MattermostState(config), remote
        ).verify()


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
async def test_daemon_holds_state_lease_during_sleep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
        handle.write(
            f'\n[[rooms]]\ncoord_room = "backlog"\nchannel_id = "{OTHER_CHANNEL_ID}"\n'
        )
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


@pytest.mark.asyncio
async def test_state_lease_prevents_two_adapter_processes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
