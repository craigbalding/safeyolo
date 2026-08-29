"""Small, fail-closed Mattermost projection for the local coord operator.

Mattermost is deliberately not a coord principal.  This adapter authenticates
one configured Mattermost user, then uses the existing *local* operator path
to append an operator envelope.  Agent-facing HTTP routes are never involved.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
import tomllib
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx

from . import api

CONFIG_VERSION = 1
ADAPTER_SCHEMA = "safeyolo.coord.mattermost.operator/v1"
PROJECTION_SCHEMA = "safeyolo.coord.mattermost.projection/v1"
ACTION_PREFIX = "!safeyolo"
MAX_MATTERMOST_POST_CHARS = 14_000
MAX_OPERATOR_TEXT_BYTES = 64 * 1024
_ID_RE = re.compile(r"^[a-z0-9]{26}$")
_ROOM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class MattermostAdapterError(RuntimeError):
    """Safe operator-facing failure without response bodies or credentials."""


class OperatorAction(StrEnum):
    ACKNOWLEDGE = "acknowledge"
    APPROVE = "approve"
    REJECT = "reject"
    DEFER = "defer"
    REVISE = "revise"
    PUBLISH = "publish"
    OPEN_ISSUE = "open-issue"


@dataclass(frozen=True)
class RoomMapping:
    coord_room: str
    channel_id: str
    backfill: bool = False


@dataclass(frozen=True)
class MattermostConfig:
    server_url: str
    bot_token_file: Path
    bot_user_id: str
    operator_user_id: str
    state_file: Path
    poll_interval_seconds: float
    rooms: tuple[RoomMapping, ...]

    @property
    def adapter_id(self) -> str:
        material = {
            "version": CONFIG_VERSION,
            "server_url": self.server_url,
            "bot_user_id": self.bot_user_id,
            "operator_user_id": self.operator_user_id,
            "rooms": [
                {"coord_room": r.coord_room, "channel_id": r.channel_id}
                for r in self.rooms
            ],
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


_ROOT_KEYS = frozenset(
    {
        "version",
        "server_url",
        "bot_token_file",
        "bot_user_id",
        "operator_user_id",
        "state_file",
        "poll_interval_seconds",
        "rooms",
    }
)
_ROOM_KEYS = frozenset({"coord_room", "channel_id", "backfill"})


def _nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MattermostAdapterError(f"{field} must be a non-empty string")
    return value.strip()


def _mattermost_id(value: Any, field: str) -> str:
    result = _nonempty_string(value, field)
    if not _ID_RE.fullmatch(result):
        raise MattermostAdapterError(f"{field} must be a 26-character Mattermost ID")
    return result


def _operator_path(value: Any, field: str, *, relative_to: Path) -> Path:
    raw = _nonempty_string(value, field)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = relative_to / path
    # Canonicalize dot segments without following the final symlink. Token and
    # state readers enforce their own no-symlink boundary on that exact path.
    return Path(os.path.abspath(path))


def load_config(path: Path) -> MattermostConfig:
    """Load a strict external TOML config; unknown keys are rejected."""

    try:
        config_path = path.expanduser().resolve(strict=True)
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, RuntimeError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise MattermostAdapterError(
            f"cannot read Mattermost adapter config: {type(exc).__name__}"
        ) from exc
    if not isinstance(raw, dict):
        raise MattermostAdapterError("Mattermost adapter config must be a TOML table")
    unknown = set(raw) - _ROOT_KEYS
    if unknown:
        raise MattermostAdapterError(
            f"unknown Mattermost adapter config keys: {', '.join(sorted(unknown))}"
        )
    if raw.get("version") != CONFIG_VERSION:
        raise MattermostAdapterError(f"version must be {CONFIG_VERSION}")

    server_url = _nonempty_string(raw.get("server_url"), "server_url").rstrip("/")
    parsed = urlparse(server_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise MattermostAdapterError(
            "server_url must be an HTTPS origin without credentials, path, query, or fragment"
        )

    rooms_raw = raw.get("rooms")
    if not isinstance(rooms_raw, list) or not rooms_raw:
        raise MattermostAdapterError("rooms must contain at least one [[rooms]] mapping")
    rooms: list[RoomMapping] = []
    seen_rooms: set[str] = set()
    seen_channels: set[str] = set()
    for index, item in enumerate(rooms_raw):
        if not isinstance(item, dict):
            raise MattermostAdapterError(f"rooms[{index}] must be a TOML table")
        unknown = set(item) - _ROOM_KEYS
        if unknown:
            raise MattermostAdapterError(
                f"unknown rooms[{index}] keys: {', '.join(sorted(unknown))}"
            )
        room = _nonempty_string(item.get("coord_room"), f"rooms[{index}].coord_room")
        if not _ROOM_RE.fullmatch(room):
            raise MattermostAdapterError(f"rooms[{index}].coord_room has invalid characters")
        channel = _mattermost_id(item.get("channel_id"), f"rooms[{index}].channel_id")
        backfill = item.get("backfill", False)
        if not isinstance(backfill, bool):
            raise MattermostAdapterError(f"rooms[{index}].backfill must be true or false")
        if room in seen_rooms or channel in seen_channels:
            raise MattermostAdapterError(
                "coord rooms and Mattermost channels must form a one-to-one mapping"
            )
        seen_rooms.add(room)
        seen_channels.add(channel)
        rooms.append(RoomMapping(room, channel, backfill))

    interval = raw.get("poll_interval_seconds", 2.0)
    if isinstance(interval, bool) or not isinstance(interval, (int, float)):
        raise MattermostAdapterError("poll_interval_seconds must be a number")
    interval = float(interval)
    if not 0.5 <= interval <= 60.0:
        raise MattermostAdapterError("poll_interval_seconds must be between 0.5 and 60")

    base = config_path.parent
    bot_user_id = _mattermost_id(raw.get("bot_user_id"), "bot_user_id")
    operator_user_id = _mattermost_id(raw.get("operator_user_id"), "operator_user_id")
    if bot_user_id == operator_user_id:
        raise MattermostAdapterError("bot_user_id and operator_user_id must differ")
    return MattermostConfig(
        server_url=server_url,
        bot_token_file=_operator_path(
            raw.get("bot_token_file"), "bot_token_file", relative_to=base
        ),
        bot_user_id=bot_user_id,
        operator_user_id=operator_user_id,
        state_file=_operator_path(raw.get("state_file"), "state_file", relative_to=base),
        poll_interval_seconds=interval,
        rooms=tuple(rooms),
    )


def read_bot_token(path: Path) -> str:
    """Read a same-UID, private, regular token file without following symlinks."""

    if path.is_symlink():
        raise MattermostAdapterError("bot_token_file must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise MattermostAdapterError(
            f"cannot read bot_token_file: {type(exc).__name__}"
        ) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise MattermostAdapterError("bot_token_file must be a regular non-symlink file")
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            raise MattermostAdapterError("bot_token_file must be owned by the current user")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise MattermostAdapterError("bot_token_file permissions must be 0600 or stricter")
        chunks: list[bytes] = []
        remaining = 4097
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if len(data) > 4096:
        raise MattermostAdapterError("bot_token_file is unreasonably large")
    try:
        token = data.decode("utf-8").strip()
    except UnicodeError as exc:
        raise MattermostAdapterError("bot_token_file must be valid UTF-8") from exc
    if not token or any(ch.isspace() for ch in token):
        raise MattermostAdapterError("bot_token_file must contain one non-empty token")
    return token


class MattermostAPI(Protocol):
    async def get_me(self) -> dict[str, Any]: ...
    async def get_user(self, user_id: str) -> dict[str, Any]: ...
    async def get_channel(self, channel_id: str) -> dict[str, Any]: ...
    async def get_posts(
        self, channel_id: str, *, since: int | None = None, per_page: int = 200
    ) -> list[dict[str, Any]]: ...
    async def create_post(self, payload: dict[str, Any]) -> dict[str, Any]: ...


class HTTPMattermostAPI:
    """Minimal official REST API v4 client using a non-admin bot token."""

    def __init__(self, config: MattermostConfig, token: str):
        self._base = f"{config.server_url}/api/v4"
        self._client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"},
            timeout=httpx.Timeout(15.0, connect=10.0),
        )

    async def __aenter__(self) -> HTTPMattermostAPI:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self._client.aclose()

    async def _request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        try:
            response = await self._client.request(
                method, f"{self._base}{path}", params=params, json=json_body
            )
        except httpx.HTTPError as exc:
            raise MattermostAdapterError(
                f"Mattermost {method} {path} failed: {type(exc).__name__}"
            ) from exc
        if response.status_code not in {200, 201}:
            raise MattermostAdapterError(
                f"Mattermost {method} {path} failed with HTTP {response.status_code}"
            )
        try:
            return response.json()
        except (ValueError, UnicodeError) as exc:
            raise MattermostAdapterError(
                f"Mattermost {method} {path} returned invalid JSON"
            ) from exc

    async def get_me(self) -> dict[str, Any]:
        return await self._request("GET", "/users/me")

    async def get_user(self, user_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/users/{user_id}")

    async def get_channel(self, channel_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/channels/{channel_id}")

    async def get_posts(
        self, channel_id: str, *, since: int | None = None, per_page: int = 200
    ) -> list[dict[str, Any]]:
        params: dict[str, Any]
        if since is None:
            params = {"page": 0, "per_page": max(1, min(per_page, 200))}
        else:
            params = {"since": max(1, since)}
        value = await self._request(
            "GET", f"/channels/{channel_id}/posts", params=params
        )
        if not isinstance(value, dict):
            raise MattermostAdapterError("Mattermost post page must be an object")
        order = value.get("order")
        posts = value.get("posts")
        if not isinstance(order, list) or not isinstance(posts, dict):
            raise MattermostAdapterError("Mattermost post page has an invalid shape")
        if len(order) != len(set(order)):
            raise MattermostAdapterError("Mattermost post page contains duplicate IDs")
        result: list[dict[str, Any]] = []
        for post_id in order:
            if not isinstance(post_id, str) or not isinstance(posts.get(post_id), dict):
                raise MattermostAdapterError("Mattermost post page correlation is malformed")
            result.append(posts[post_id])
        return result

    async def create_post(self, payload: dict[str, Any]) -> dict[str, Any]:
        value = await self._request("POST", "/posts", json_body=payload)
        if not isinstance(value, dict):
            raise MattermostAdapterError("Mattermost create-post response must be an object")
        return value


def _prepare_state_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_st = path.parent.stat()
    if not stat.S_ISDIR(parent_st.st_mode):
        raise MattermostAdapterError("state_file parent must be a directory")
    if hasattr(os, "getuid") and parent_st.st_uid != os.getuid():
        raise MattermostAdapterError("state_file parent must be owned by the current user")
    if stat.S_IMODE(parent_st.st_mode) & 0o022:
        raise MattermostAdapterError("state_file parent must not be group/world writable")
    if path.exists() or path.is_symlink():
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise MattermostAdapterError("state_file must be a regular non-symlink file")
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            raise MattermostAdapterError("state_file must be owned by the current user")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise MattermostAdapterError("state_file permissions must be 0600 or stricter")
        return
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)


class MattermostState:
    """Durable duplicate/loop suppression, separate from authoritative coord."""

    def __init__(self, config: MattermostConfig):
        self.path = config.state_file
        _prepare_state_file(self.path)
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS room_state (
                    coord_room TEXT PRIMARY KEY,
                    channel_id TEXT NOT NULL UNIQUE,
                    coord_cursor INTEGER NOT NULL DEFAULT 0 CHECK(coord_cursor >= 0),
                    inbound_since INTEGER NOT NULL DEFAULT 0 CHECK(inbound_since >= 0),
                    initialized INTEGER NOT NULL DEFAULT 0 CHECK(initialized IN (0, 1))
                );
                CREATE TABLE IF NOT EXISTS outbound_projection (
                    coord_msg_id TEXT PRIMARY KEY,
                    coord_room TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    projection_key TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'sent')),
                    mattermost_post_id TEXT UNIQUE,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS inbound_post (
                    mattermost_post_id TEXT PRIMARY KEY,
                    coord_room TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ignored', 'pending', 'sent')),
                    reason TEXT,
                    coord_msg_id TEXT,
                    created_at INTEGER NOT NULL
                );
                """
            )
            existing = conn.execute(
                "SELECT value FROM metadata WHERE key = 'adapter_id'"
            ).fetchone()
            if existing is None:
                conn.execute(
                    "INSERT INTO metadata(key, value) VALUES ('adapter_id', ?)",
                    (config.adapter_id,),
                )
            elif existing["value"] != config.adapter_id:
                raise MattermostAdapterError(
                    "state_file belongs to a different server/operator/room mapping"
                )
            expected = {(room.coord_room, room.channel_id) for room in config.rooms}
            actual = {
                (row["coord_room"], row["channel_id"])
                for row in conn.execute("SELECT coord_room, channel_id FROM room_state")
            }
            if actual and actual != expected:
                raise MattermostAdapterError("state_file room mapping differs from config")
            for room in config.rooms:
                conn.execute(
                    "INSERT OR IGNORE INTO room_state(coord_room, channel_id) VALUES (?, ?)",
                    (room.coord_room, room.channel_id),
                )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), isolation_level=None, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def lease(self):
        """Exclude another adapter process for the complete sync transaction."""

        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags)
        except OSError as exc:
            raise MattermostAdapterError(
                f"cannot open state_file lease: {type(exc).__name__}"
            ) from exc
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise MattermostAdapterError(
                    "another Mattermost adapter process owns this state_file"
                ) from exc
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def room_state(self, room: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM room_state WHERE coord_room = ?", (room,)
            ).fetchone()
        assert row is not None
        return dict(row)

    def initialize_room(self, room: str, *, coord_cursor: int, inbound_since: int) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT initialized FROM room_state WHERE coord_room = ?", (room,)
            ).fetchone()
            if row is not None and not row["initialized"]:
                conn.execute(
                    """UPDATE room_state SET coord_cursor = ?, inbound_since = ?, initialized = 1
                       WHERE coord_room = ?""",
                    (coord_cursor, inbound_since, room),
                )
            conn.execute("COMMIT")

    def set_coord_cursor(self, room: str, cursor: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE room_state SET coord_cursor = ? WHERE coord_room = ?",
                (cursor, room),
            )

    def set_inbound_since(self, room: str, value: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE room_state SET inbound_since = max(inbound_since, ?) WHERE coord_room = ?",
                (value, room),
            )

    def outbound(self, msg_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM outbound_projection WHERE coord_msg_id = ?", (msg_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def begin_outbound(
        self, *, msg_id: str, room: str, channel_id: str, projection_key: str
    ) -> dict[str, Any]:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT OR IGNORE INTO outbound_projection
                   (coord_msg_id, coord_room, channel_id, projection_key, status, created_at)
                   VALUES (?, ?, ?, ?, 'pending', ?)""",
                (msg_id, room, channel_id, projection_key, int(time.time() * 1000)),
            )
            row = conn.execute(
                "SELECT * FROM outbound_projection WHERE coord_msg_id = ?", (msg_id,)
            ).fetchone()
            conn.execute("COMMIT")
        assert row is not None
        return dict(row)

    def finish_outbound(self, msg_id: str, post_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """UPDATE outbound_projection SET status = 'sent', mattermost_post_id = ?
                   WHERE coord_msg_id = ? AND status = 'pending'""",
                (post_id, msg_id),
            )

    def pending_outbound(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM outbound_projection WHERE status = 'pending' ORDER BY created_at"
            ).fetchall()
        return [dict(row) for row in rows]

    def projection_for_root(
        self, post_id: str, *, room: str, channel_id: str
    ) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """SELECT * FROM outbound_projection
                   WHERE mattermost_post_id = ? AND coord_room = ? AND channel_id = ?
                     AND status = 'sent'""",
                (post_id, room, channel_id),
            ).fetchone()
        return dict(row) if row is not None else None

    def inbound(self, post_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM inbound_post WHERE mattermost_post_id = ?", (post_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def ignore_inbound(self, post_id: str, room: str, reason: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO inbound_post
                   (mattermost_post_id, coord_room, status, reason, created_at)
                   VALUES (?, ?, 'ignored', ?, ?)""",
                (post_id, room, reason, int(time.time() * 1000)),
            )

    def begin_inbound(self, post_id: str, room: str) -> bool:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT 1 FROM inbound_post WHERE mattermost_post_id = ?", (post_id,)
            ).fetchone()
            if existing is None:
                conn.execute(
                    """INSERT INTO inbound_post
                       (mattermost_post_id, coord_room, status, created_at)
                       VALUES (?, ?, 'pending', ?)""",
                    (post_id, room, int(time.time() * 1000)),
                )
            conn.execute("COMMIT")
        return existing is None

    def finish_inbound(self, post_id: str, coord_msg_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """UPDATE inbound_post SET status = 'sent', coord_msg_id = ?
                   WHERE mattermost_post_id = ? AND status = 'pending'""",
                (coord_msg_id, post_id),
            )

    def pending_inbound(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM inbound_post WHERE status = 'pending' ORDER BY created_at"
            ).fetchall()
        return [dict(row) for row in rows]


def _safe_json(value: Any, *, indent: int | None = None) -> str:
    rendered = json.dumps(value, ensure_ascii=True, sort_keys=True, indent=indent)
    # Mattermost does not expand mentions inside code spans today, but make
    # that safety independent of renderer settings and future Markdown changes.
    return rendered.replace("@", r"\u0040").replace("<", r"\u003c").replace(">", r"\u003e")


def _fenced(label: str, value: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"**{label}**\n{fence}json\n{value}\n{fence}"


def render_envelope(envelope: dict[str, Any], room: str) -> str:
    """Render canonical attribution apart from inert, untrusted body text."""

    canonical_keys = (
        "msg_id",
        "sent_at",
        "sender_kind",
        "sender_agent_id",
        "sender_agent_name",
        "origin_instance_id",
        "content_type",
    )
    if not isinstance(envelope, dict) or any(key not in envelope for key in canonical_keys):
        raise MattermostAdapterError("coord envelope is missing canonical fields")
    body = envelope.get("body")
    if not isinstance(body, str):
        raise MattermostAdapterError("coord envelope body must be a string")
    metadata = {"coord_room": room, **{key: envelope[key] for key in canonical_keys}}
    body_bytes = body.encode("utf-8")
    body_value: dict[str, Any] = {"untrusted_body": body}
    rendered = _fenced("SafeYolo canonical envelope", _safe_json(metadata, indent=2))
    rendered += "\n\n" + _fenced("Untrusted sender-authored body", _safe_json(body_value, indent=2))
    if len(rendered) <= MAX_MATTERMOST_POST_CHARS:
        return rendered
    digest = hashlib.sha256(body_bytes).hexdigest()
    allowance = max(0, MAX_MATTERMOST_POST_CHARS - len(rendered) + len(body) - 512)
    while True:
        body_value = {
            "untrusted_body_prefix": body[:allowance],
            "truncated": True,
            "original_utf8_bytes": len(body_bytes),
            "sha256": digest,
        }
        rendered = _fenced("SafeYolo canonical envelope", _safe_json(metadata, indent=2))
        rendered += "\n\n" + _fenced(
            "Untrusted sender-authored body", _safe_json(body_value, indent=2)
        )
        if len(rendered) <= MAX_MATTERMOST_POST_CHARS or allowance == 0:
            return rendered
        allowance = max(0, allowance - (len(rendered) - MAX_MATTERMOST_POST_CHARS))


def _projection_key(adapter_id: str, room: str, msg_id: str) -> str:
    return hashlib.sha256(f"{adapter_id}\0{room}\0{msg_id}".encode()).hexdigest()


def _post_id(post: dict[str, Any]) -> str:
    return _mattermost_id(post.get("id"), "post.id")


def _post_timestamp(post: dict[str, Any]) -> int:
    value = post.get("update_at")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MattermostAdapterError("Mattermost post update_at is invalid")
    return value


def _is_active_timestamp(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == 0


def _validate_created_post(
    post: dict[str, Any], *, config: MattermostConfig, channel_id: str,
    projection_key: str,
) -> str:
    post_id = _post_id(post)
    if post.get("user_id") != config.bot_user_id or post.get("channel_id") != channel_id:
        raise MattermostAdapterError("Mattermost create-post response attribution is ambiguous")
    marker = post.get("props", {}).get("safeyolo_coord") if isinstance(post.get("props"), dict) else None
    if not isinstance(marker, dict) or marker.get("projection_key") != projection_key:
        raise MattermostAdapterError("Mattermost create-post response lost projection correlation")
    return post_id


def _parse_action(text: str) -> tuple[OperatorAction | None, str]:
    if not text.startswith(ACTION_PREFIX):
        return None, text
    if not text.startswith(f"{ACTION_PREFIX} "):
        raise MattermostAdapterError("malformed typed action")
    command, _, note = text[len(ACTION_PREFIX) + 1 :].partition(" ")
    try:
        action = OperatorAction(command)
    except ValueError as exc:
        raise MattermostAdapterError("unknown typed action") from exc
    return action, note.strip()


class MattermostAdapter:
    def __init__(
        self, config: MattermostConfig, state: MattermostState, client: MattermostAPI
    ):
        self.config = config
        self.state = state
        self.client = client

    async def verify(self) -> None:
        me = await self.client.get_me()
        if (
            not isinstance(me, dict)
            or me.get("id") != self.config.bot_user_id
            or me.get("is_bot") is not True
            or not _is_active_timestamp(me.get("delete_at"))
        ):
            raise MattermostAdapterError("bot token does not identify the configured active bot")
        await self._verify_operator()
        for mapping in self.config.rooms:
            channel = await self.client.get_channel(mapping.channel_id)
            if (
                not isinstance(channel, dict)
                or channel.get("id") != mapping.channel_id
                or not _is_active_timestamp(channel.get("delete_at"))
            ):
                raise MattermostAdapterError(
                    f"configured channel for coord room {mapping.coord_room!r} is unavailable"
                )
            # A read proves the bot token can observe the mapped channel without
            # creating trial traffic. --once exercises create permission.
            await self.client.get_posts(mapping.channel_id, per_page=1)
            membership = api.join_room(mapping.coord_room, "operator", "operator")
            permissions = membership.get("permissions", [])
            if not isinstance(permissions, list) or not {"send", "receive"}.issubset(permissions):
                raise MattermostAdapterError(
                    f"local coord operator lacks send+receive on {mapping.coord_room!r}"
                )

    async def _verify_operator(self) -> None:
        operator = await self.client.get_user(self.config.operator_user_id)
        if (
            not isinstance(operator, dict)
            or operator.get("id") != self.config.operator_user_id
            or operator.get("is_bot") is not False
            or not _is_active_timestamp(operator.get("delete_at"))
        ):
            raise MattermostAdapterError("configured Mattermost operator is not one active human user")

    async def _bootstrap_room(self, mapping: RoomMapping) -> None:
        current = self.state.room_state(mapping.coord_room)
        if current["initialized"]:
            return
        posts = await self.client.get_posts(mapping.channel_id, per_page=1)
        inbound_since = max((_post_timestamp(post) for post in posts), default=0) + 1
        cursor = 0
        if not mapping.backfill:
            while True:
                page = await api.read_room(
                    mapping.coord_room, "operator", "operator", since_sequence=cursor, limit=200
                )
                cursor = int(page["next_cursor"])
                if not page["has_more"]:
                    break
        self.state.initialize_room(
            mapping.coord_room, coord_cursor=cursor, inbound_since=inbound_since
        )

    async def _reconcile_pending(self) -> None:
        for pending in self.state.pending_outbound():
            posts = await self.client.get_posts(
                pending["channel_id"], since=max(1, pending["created_at"] - 60_000)
            )
            matches = []
            for post in posts:
                marker = post.get("props", {}).get("safeyolo_coord") if isinstance(post.get("props"), dict) else None
                if isinstance(marker, dict) and marker.get("projection_key") == pending["projection_key"]:
                    matches.append(post)
            if len(matches) > 1:
                raise MattermostAdapterError("duplicate Mattermost projection requires operator reconciliation")
            if not matches:
                raise MattermostAdapterError(
                    "uncertain Mattermost projection remains pending; refusing an automatic retry"
                )
            post_id = _validate_created_post(
                matches[0], config=self.config, channel_id=pending["channel_id"],
                projection_key=pending["projection_key"],
            )
            self.state.finish_outbound(pending["coord_msg_id"], post_id)

    def _inbound_body(
        self, *, mapping: RoomMapping, post: dict[str, Any], target_msg_id: str
    ) -> str:
        text = post.get("message")
        if not isinstance(text, str) or not text.strip():
            raise MattermostAdapterError("operator reply must contain non-empty text")
        if len(text.encode("utf-8")) > MAX_OPERATOR_TEXT_BYTES:
            raise MattermostAdapterError("operator reply is too large")
        action, note = _parse_action(text)
        payload = {
            "schema": ADAPTER_SCHEMA,
            "adapter_id": self.config.adapter_id,
            "kind": "action" if action is not None else "reply",
            "action": action.value if action is not None else None,
            "text": note,
            "correlation": {
                "coord_msg_id": target_msg_id,
                "mattermost_post_id": post["id"],
                "mattermost_root_post_id": post["root_id"],
                "mattermost_channel_id": mapping.channel_id,
            },
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    async def _process_inbound_post(
        self, mapping: RoomMapping, post: dict[str, Any]
    ) -> None:
        post_id = _post_id(post)
        existing = self.state.inbound(post_id)
        if existing is not None and existing["status"] == "pending":
            raise MattermostAdapterError(
                "uncertain coord append remains pending; refusing an automatic replay"
            )
        if existing is not None:
            return
        if post.get("channel_id") != mapping.channel_id:
            self.state.ignore_inbound(post_id, mapping.coord_room, "channel_mismatch")
            return
        required_ints = ("create_at", "update_at", "edit_at", "delete_at")
        if any(isinstance(post.get(k), bool) or not isinstance(post.get(k), int) for k in required_ints):
            self.state.ignore_inbound(post_id, mapping.coord_room, "malformed_timestamps")
            return
        if post["delete_at"] != 0 or post["edit_at"] != 0 or post["update_at"] != post["create_at"]:
            self.state.ignore_inbound(post_id, mapping.coord_room, "edited_or_deleted")
            return
        if post.get("user_id") != self.config.operator_user_id:
            self.state.ignore_inbound(post_id, mapping.coord_room, "not_configured_operator")
            return
        root_id = post.get("root_id")
        if not isinstance(root_id, str) or not _ID_RE.fullmatch(root_id):
            self.state.ignore_inbound(post_id, mapping.coord_room, "unmapped_thread")
            return
        projection = self.state.projection_for_root(
            root_id, room=mapping.coord_room, channel_id=mapping.channel_id
        )
        if projection is None:
            self.state.ignore_inbound(post_id, mapping.coord_room, "unmapped_thread")
            return
        try:
            body = self._inbound_body(
                mapping=mapping, post=post, target_msg_id=projection["coord_msg_id"]
            )
        except MattermostAdapterError:
            self.state.ignore_inbound(post_id, mapping.coord_room, "malformed_body_or_action")
            return
        if not self.state.begin_inbound(post_id, mapping.coord_room):
            return
        # Deliberately the same trusted local operator call as coord chat.
        # There is no agent credential/path to impersonate here.
        result = await api.send(
            mapping.coord_room,
            "operator",
            None,
            body,
            declared_content_type="text/plain",
            notify="room",
        )
        envelope = result.get("envelope")
        if not isinstance(envelope, dict) or not isinstance(envelope.get("msg_id"), str):
            raise MattermostAdapterError("coord send returned an invalid envelope")
        self.state.finish_inbound(post_id, envelope["msg_id"])

    async def _poll_inbound(self, mapping: RoomMapping) -> None:
        # Re-establish the remote identity boundary on every bounded cycle.
        # A user deactivated after daemon startup must never retain the right
        # to produce new canonical coord operator envelopes.
        await self._verify_operator()
        current = self.state.room_state(mapping.coord_room)
        since = max(1, int(current["inbound_since"]) - 5_000)
        posts = await self.client.get_posts(mapping.channel_id, since=since)
        posts.sort(key=lambda post: (_post_timestamp(post), str(post.get("id", ""))))
        for post in posts:
            await self._process_inbound_post(mapping, post)
        observed = max((_post_timestamp(post) for post in posts), default=int(current["inbound_since"]))
        self.state.set_inbound_since(mapping.coord_room, observed + 1)

    def _is_own_inbound(self, envelope: dict[str, Any]) -> bool:
        if envelope.get("sender_kind") != "operator" or envelope.get("content_type") != "text/plain":
            return False
        try:
            payload = json.loads(envelope.get("body", ""))
        except (TypeError, ValueError):
            return False
        return (
            isinstance(payload, dict)
            and payload.get("schema") == ADAPTER_SCHEMA
            and payload.get("adapter_id") == self.config.adapter_id
        )

    async def _project_outbound(self, mapping: RoomMapping) -> None:
        current = self.state.room_state(mapping.coord_room)
        cursor = int(current["coord_cursor"])
        while True:
            page = await api.read_room(
                mapping.coord_room, "operator", "operator", since_sequence=cursor, limit=50
            )
            for envelope in page["messages"]:
                msg_id = envelope.get("msg_id")
                sequence = envelope.get("sequence")
                if not isinstance(msg_id, str) or not isinstance(sequence, int):
                    raise MattermostAdapterError("coord read returned an invalid envelope")
                existing = self.state.outbound(msg_id)
                if self._is_own_inbound(envelope) or (existing and existing["status"] == "sent"):
                    cursor = sequence
                    self.state.set_coord_cursor(mapping.coord_room, cursor)
                    continue
                if existing and existing["status"] == "pending":
                    raise MattermostAdapterError(
                        "uncertain Mattermost projection remains pending; refusing an automatic retry"
                    )
                projection_key = _projection_key(
                    self.config.adapter_id, mapping.coord_room, msg_id
                )
                self.state.begin_outbound(
                    msg_id=msg_id,
                    room=mapping.coord_room,
                    channel_id=mapping.channel_id,
                    projection_key=projection_key,
                )
                payload = {
                    "channel_id": mapping.channel_id,
                    "message": render_envelope(envelope, mapping.coord_room),
                    "props": {
                        "safeyolo_coord": {
                            "schema": PROJECTION_SCHEMA,
                            "adapter_id": self.config.adapter_id,
                            "projection_key": projection_key,
                            "coord_room": mapping.coord_room,
                            "coord_msg_id": msg_id,
                        }
                    },
                }
                post = await self.client.create_post(payload)
                post_id = _validate_created_post(
                    post,
                    config=self.config,
                    channel_id=mapping.channel_id,
                    projection_key=projection_key,
                )
                self.state.finish_outbound(msg_id, post_id)
                cursor = sequence
                self.state.set_coord_cursor(mapping.coord_room, cursor)
            if not page["has_more"]:
                break

    async def _run_cycle(self) -> None:
        if self.state.pending_inbound():
            raise MattermostAdapterError(
                "uncertain coord append remains pending; refusing an automatic replay"
            )
        for mapping in self.config.rooms:
            await self._bootstrap_room(mapping)
        await self._reconcile_pending()
        for mapping in self.config.rooms:
            await self._poll_inbound(mapping)
            await self._project_outbound(mapping)

    async def run_once(self, *, verify: bool = False) -> None:
        with self.state.lease():
            if verify:
                await self.verify()
            await self._run_cycle()

    async def run_forever(self) -> None:
        # The daemon owns one state file continuously, including quiet sleep.
        # A second process cannot interleave cycles and race pending records.
        with self.state.lease():
            await self.verify()
            while True:
                await self._run_cycle()
                await asyncio.sleep(self.config.poll_interval_seconds)
